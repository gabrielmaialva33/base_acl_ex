defmodule BaseAclEx.Infrastructure.Security.Services.RateLimiterTest do
  use ExUnit.Case, async: false

  alias BaseAclEx.Infrastructure.Security.Services.RateLimiter
  alias BaseAclEx.Infrastructure.Security.Entities.RateLimit

  @cache_name :rate_limiter_cache

  setup do
    # Ensure cache is clean before each test
    Cachex.clear(@cache_name)
    :ok
  end

  describe "check_rate_limit/2" do
    test "allows first request" do
      assert {:ok, rate_limit} = RateLimiter.check_rate_limit("test_ip", max_requests: 5)
      assert rate_limit.identifier == "test_ip"
      assert length(rate_limit.requests) == 1
      assert rate_limit.max_requests == 5
    end

    test "allows requests within limit" do
      identifier = "test_ip_2"

      # Make 3 requests
      for _ <- 1..3 do
        assert {:ok, _} = RateLimiter.check_rate_limit(identifier, max_requests: 5)
      end

      # Should still be allowed
      assert {:ok, rate_limit} = RateLimiter.check_rate_limit(identifier, max_requests: 5)
      assert length(rate_limit.requests) == 4
    end

    test "blocks requests exceeding limit" do
      identifier = "test_ip_3"

      # Make 5 requests (max limit)
      for _ <- 1..5 do
        assert {:ok, _} = RateLimiter.check_rate_limit(identifier, max_requests: 5)
      end

      # 6th request should be blocked
      assert {:error, rate_limit} = RateLimiter.check_rate_limit(identifier, max_requests: 5)
      assert length(rate_limit.requests) == 5
    end

    test "sliding window cleans old requests" do
      identifier = "test_ip_4"
      # Very short window for testing
      window_ms = 100

      # Make 3 requests
      for _ <- 1..3 do
        assert {:ok, _} =
                 RateLimiter.check_rate_limit(identifier,
                   max_requests: 3,
                   window_ms: window_ms
                 )
      end

      # Wait for window to expire
      Process.sleep(window_ms + 10)

      # Should allow new requests as old ones are outside window
      assert {:ok, rate_limit} =
               RateLimiter.check_rate_limit(identifier,
                 max_requests: 3,
                 window_ms: window_ms
               )

      assert length(rate_limit.requests) == 1
    end

    test "handles cache errors gracefully" do
      # Stop the cache to simulate error
      Cachex.stop(@cache_name)

      # Should still allow request but log warning
      assert {:ok, rate_limit} = RateLimiter.check_rate_limit("test_ip")
      assert rate_limit.identifier == "test_ip"

      # Restart cache for other tests
      BaseAclEx.Infrastructure.Security.Cache.RateLimiterCache.start_link()
    end
  end

  describe "reset_rate_limit/1" do
    test "removes rate limit entry" do
      identifier = "test_reset"

      # Create some requests
      RateLimiter.check_rate_limit(identifier, max_requests: 5)
      RateLimiter.check_rate_limit(identifier, max_requests: 5)

      # Reset should clear the limit
      RateLimiter.reset_rate_limit(identifier)

      # Next request should be treated as first
      assert {:ok, rate_limit} = RateLimiter.check_rate_limit(identifier, max_requests: 5)
      assert length(rate_limit.requests) == 1
    end
  end

  describe "get_rate_limit_status/2" do
    test "returns current status without incrementing" do
      identifier = "test_status"

      # Make some requests
      RateLimiter.check_rate_limit(identifier, max_requests: 5)
      RateLimiter.check_rate_limit(identifier, max_requests: 5)

      # Get status should not increment
      status = RateLimiter.get_rate_limit_status(identifier, max_requests: 5)
      assert length(status.requests) == 2

      # Get status again - should be the same
      status2 = RateLimiter.get_rate_limit_status(identifier, max_requests: 5)
      assert length(status2.requests) == 2
    end

    test "returns empty status for non-existent identifier" do
      status = RateLimiter.get_rate_limit_status("nonexistent", max_requests: 5)
      assert length(status.requests) == 0
      assert status.max_requests == 5
    end
  end

  describe "build_identifier/2" do
    test "builds IP-based identifier" do
      conn = %Plug.Conn{remote_ip: {127, 0, 0, 1}}

      identifier = RateLimiter.build_identifier(conn, strategy: :ip)
      assert identifier == "127.0.0.1"
    end

    test "handles x-forwarded-for header" do
      conn = %Plug.Conn{
        remote_ip: {127, 0, 0, 1},
        req_headers: [{"x-forwarded-for", "192.168.1.1, 10.0.0.1"}]
      }

      identifier = RateLimiter.build_identifier(conn, strategy: :ip)
      assert identifier == "192.168.1.1"
    end

    test "builds user-based identifier when authenticated" do
      user = %{id: 123}

      conn = %Plug.Conn{remote_ip: {127, 0, 0, 1}}
      conn = Guardian.Plug.put_current_resource(conn, user)

      identifier = RateLimiter.build_identifier(conn, strategy: :user)
      assert identifier == "user:123"
    end

    test "falls back to IP for unauthenticated users with user strategy" do
      conn = %Plug.Conn{remote_ip: {127, 0, 0, 1}}

      identifier = RateLimiter.build_identifier(conn, strategy: :user)
      assert identifier == "127.0.0.1"
    end

    test "builds endpoint-specific identifiers" do
      conn = %Plug.Conn{
        remote_ip: {127, 0, 0, 1},
        method: "POST",
        request_path: "/api/v1/auth/login"
      }

      identifier = RateLimiter.build_identifier(conn, strategy: :ip_and_endpoint)
      assert identifier == "127.0.0.1:POST:/api/v1/auth/login"
    end
  end

  describe "should_bypass?/1" do
    test "returns false for unauthenticated users" do
      conn = %Plug.Conn{}
      refute RateLimiter.should_bypass?(conn)
    end

    test "returns true for admin users" do
      admin_user = %{
        id: 1,
        roles: [%{name: "admin"}]
      }

      conn = %Plug.Conn{}
      conn = Guardian.Plug.put_current_resource(conn, admin_user)

      assert RateLimiter.should_bypass?(conn)
    end

    test "returns true for users with bypass permission" do
      bypass_user = %{
        id: 2,
        permissions: [%{name: "rate_limit_bypass"}]
      }

      conn = %Plug.Conn{}
      conn = Guardian.Plug.put_current_resource(conn, bypass_user)

      assert RateLimiter.should_bypass?(conn)
    end

    test "returns false for regular users" do
      regular_user = %{
        id: 3,
        roles: [%{name: "user"}],
        permissions: [%{name: "read_posts"}]
      }

      conn = %Plug.Conn{}
      conn = Guardian.Plug.put_current_resource(conn, regular_user)

      refute RateLimiter.should_bypass?(conn)
    end
  end
end
