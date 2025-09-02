defmodule BaseAclExWeb.Plugs.RateLimiterTest do
  use BaseAclExWeb.ConnCase, async: false

  alias BaseAclEx.Infrastructure.Security.Plugs.RateLimiter

  @cache_name :rate_limiter_cache

  setup do
    # Ensure cache is clean and rate limiting is enabled for tests
    Cachex.clear(@cache_name)
    Application.put_env(:base_acl_ex, :rate_limiting_enabled, true)

    on_exit(fn ->
      Application.put_env(:base_acl_ex, :rate_limiting_enabled, false)
    end)

    :ok
  end

  describe "rate limiting with presets" do
    test "auth_limits preset works correctly", %{conn: conn} do
      opts = RateLimiter.init(:auth_limits)

      # Make requests up to the limit (10 for auth)
      conn_results =
        for _ <- 1..10 do
          RateLimiter.call(conn, opts)
        end

      # All should pass
      assert Enum.all?(conn_results, &(&1.status != 429))

      # 11th request should be blocked
      blocked_conn = RateLimiter.call(conn, opts)
      assert blocked_conn.status == 429
      assert blocked_conn.halted == true
    end

    test "api_limits preset allows more requests", %{conn: conn} do
      opts = RateLimiter.init(:api_limits)

      # Make some requests (should allow 1000 for API)
      conn_results =
        for _ <- 1..50 do
          RateLimiter.call(conn, opts)
        end

      # All should pass
      assert Enum.all?(conn_results, &(&1.status != 429))
      assert Enum.all?(conn_results, &(!&1.halted))
    end

    test "strict_limits preset has tighter restrictions", %{conn: conn} do
      opts = RateLimiter.init(:strict_limits)

      # Make requests up to the limit (30 for strict)
      conn_results =
        for _ <- 1..30 do
          RateLimiter.call(conn, opts)
        end

      # All should pass
      assert Enum.all?(conn_results, &(&1.status != 429))

      # 31st request should be blocked
      blocked_conn = RateLimiter.call(conn, opts)
      assert blocked_conn.status == 429
    end
  end

  describe "rate limit headers" do
    test "adds correct rate limit headers on success", %{conn: conn} do
      opts = RateLimiter.init(max_requests: 10, window_ms: 60_000)

      result_conn = RateLimiter.call(conn, opts)

      assert get_resp_header(result_conn, "x-ratelimit-limit") == ["10"]
      assert get_resp_header(result_conn, "x-ratelimit-remaining") == ["9"]
      assert get_resp_header(result_conn, "x-ratelimit-window") == ["60"]

      reset_time = get_resp_header(result_conn, "x-ratelimit-reset") |> List.first()
      assert String.to_integer(reset_time) >= 0
    end

    test "adds correct headers when rate limited", %{conn: conn} do
      opts = RateLimiter.init(max_requests: 2, window_ms: 60_000)

      # Make 2 requests to reach limit
      RateLimiter.call(conn, opts)
      RateLimiter.call(conn, opts)

      # 3rd request should be blocked with headers
      blocked_conn = RateLimiter.call(conn, opts)

      assert blocked_conn.status == 429
      assert get_resp_header(blocked_conn, "x-ratelimit-limit") == ["2"]
      assert get_resp_header(blocked_conn, "x-ratelimit-remaining") == ["0"]
    end

    test "adds bypass headers for admin users", %{conn: conn} do
      admin_user = %{
        id: 1,
        roles: [%{name: "admin"}]
      }

      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      opts = RateLimiter.init(:auth_limits)

      result_conn = RateLimiter.call(conn, opts)

      assert get_resp_header(result_conn, "x-ratelimit-bypass") == ["admin"]
      assert get_resp_header(result_conn, "x-ratelimit-limit") == ["unlimited"]
      assert get_resp_header(result_conn, "x-ratelimit-remaining") == ["unlimited"]
    end
  end

  describe "admin bypass functionality" do
    test "bypasses rate limiting for admin users", %{conn: conn} do
      admin_user = %{
        id: 1,
        roles: [%{name: "admin"}]
      }

      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      opts = RateLimiter.init(max_requests: 2, window_ms: 60_000, bypass_admin: true)

      # Make many requests - all should pass
      conn_results =
        for _ <- 1..10 do
          RateLimiter.call(conn, opts)
        end

      assert Enum.all?(conn_results, &(&1.status != 429))
      assert Enum.all?(conn_results, &(!&1.halted))
    end

    test "bypasses rate limiting for users with bypass permission", %{conn: conn} do
      bypass_user = %{
        id: 2,
        permissions: [%{name: "rate_limit_bypass"}]
      }

      conn = Guardian.Plug.put_current_resource(conn, bypass_user)
      opts = RateLimiter.init(max_requests: 2, window_ms: 60_000, bypass_admin: true)

      # Make many requests - all should pass
      conn_results =
        for _ <- 1..10 do
          RateLimiter.call(conn, opts)
        end

      assert Enum.all?(conn_results, &(&1.status != 429))
    end

    test "respects bypass_admin: false setting", %{conn: conn} do
      admin_user = %{
        id: 1,
        roles: [%{name: "admin"}]
      }

      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      opts = RateLimiter.init(max_requests: 2, window_ms: 60_000, bypass_admin: false)

      # Make requests up to limit
      RateLimiter.call(conn, opts)
      RateLimiter.call(conn, opts)

      # Should be rate limited despite being admin
      blocked_conn = RateLimiter.call(conn, opts)
      assert blocked_conn.status == 429
    end
  end

  describe "different rate limiting strategies" do
    test "IP strategy uses client IP", %{conn: conn} do
      conn = %{conn | remote_ip: {192, 168, 1, 100}}
      opts = RateLimiter.init(max_requests: 5, strategy: :ip)

      # Make requests
      for _ <- 1..5 do
        RateLimiter.call(conn, opts)
      end

      # Should be blocked on 6th request
      blocked_conn = RateLimiter.call(conn, opts)
      assert blocked_conn.status == 429
    end

    test "user strategy uses user ID when authenticated", %{conn: conn} do
      user = %{id: 123}
      conn = Guardian.Plug.put_current_resource(conn, user)

      opts = RateLimiter.init(max_requests: 3, strategy: :user)

      # Make requests
      for _ <- 1..3 do
        RateLimiter.call(conn, opts)
      end

      # Should be blocked
      blocked_conn = RateLimiter.call(conn, opts)
      assert blocked_conn.status == 429
    end

    test "user strategy falls back to IP for unauthenticated", %{conn: conn} do
      opts = RateLimiter.init(max_requests: 2, strategy: :user)

      # Make requests as unauthenticated user
      RateLimiter.call(conn, opts)
      RateLimiter.call(conn, opts)

      # Should be blocked based on IP
      blocked_conn = RateLimiter.call(conn, opts)
      assert blocked_conn.status == 429
    end
  end

  describe "configuration override" do
    test "respects global rate limiting disabled", %{conn: conn} do
      Application.put_env(:base_acl_ex, :rate_limiting_enabled, false)

      opts = RateLimiter.init(max_requests: 1, window_ms: 60_000)

      # Should pass even after exceeding limit
      for _ <- 1..10 do
        result_conn = RateLimiter.call(conn, opts)
        assert result_conn.status != 429
        assert !result_conn.halted
      end
    end
  end

  describe "error responses" do
    test "returns proper JSON error when rate limited", %{conn: conn} do
      opts = RateLimiter.init(max_requests: 1, window_ms: 60_000)

      # First request passes
      RateLimiter.call(conn, opts)

      # Second request blocked
      blocked_conn = RateLimiter.call(conn, opts)

      assert blocked_conn.status == 429
      assert get_resp_header(blocked_conn, "content-type") == ["application/json; charset=utf-8"]

      response = json_response(blocked_conn, 429)

      assert %{
               "error" => %{
                 "message" => "Rate limit exceeded. Try again later.",
                 "type" => "rate_limit_exceeded",
                 "retry_after" => retry_after
               }
             } = response

      assert is_integer(retry_after)
    end
  end
end
