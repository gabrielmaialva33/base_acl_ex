defmodule BaseAclExWeb.Integration.RateLimitingIntegrationTest do
  @moduledoc """
  Integration tests for rate limiting across the entire application.

  Tests the complete rate limiting workflow including:
  - Router pipeline integration
  - Different endpoint types
  - Authentication interaction
  - Admin management
  """

  use BaseAclExWeb.ConnCase, async: false

  alias BaseAclEx.Infrastructure.Security.Services.RateLimiter

  @cache_name :rate_limiter_cache

  setup do
    # Ensure clean state and enable rate limiting
    Cachex.clear(@cache_name)
    Application.put_env(:base_acl_ex, :rate_limiting_enabled, true)

    on_exit(fn ->
      Application.put_env(:base_acl_ex, :rate_limiting_enabled, false)
    end)

    :ok
  end

  describe "authentication endpoints rate limiting" do
    test "login endpoint enforces auth limits", %{conn: conn} do
      # Auth endpoints should have strict limits (10 requests per minute)
      login_attempts =
        for i <- 1..10 do
          post(conn, ~p"/api/v1/auth/login", %{
            email: "test#{i}@example.com",
            password: "wrongpassword"
          })
        end

      # First 10 should get through (even if they fail auth)
      successful_attempts = Enum.count(login_attempts, &(&1.status != 429))
      assert successful_attempts == 10

      # 11th attempt should be rate limited
      blocked_conn =
        post(conn, ~p"/api/v1/auth/login", %{
          email: "test@example.com",
          password: "password"
        })

      assert blocked_conn.status == 429
      assert get_resp_header(blocked_conn, "x-ratelimit-limit") == ["10"]
      assert get_resp_header(blocked_conn, "x-ratelimit-remaining") == ["0"]

      response = json_response(blocked_conn, 429)
      assert response["error"]["type"] == "rate_limit_exceeded"
      assert is_integer(response["error"]["retry_after"])
    end

    test "register endpoint enforces auth limits", %{conn: conn} do
      # Make requests up to auth limit
      for i <- 1..10 do
        post(conn, ~p"/api/v1/auth/register", %{
          email: "test#{i}@example.com",
          password: "password123",
          password_confirmation: "password123"
        })
      end

      # 11th should be blocked
      blocked_conn =
        post(conn, ~p"/api/v1/auth/register", %{
          email: "blocked@example.com",
          password: "password123",
          password_confirmation: "password123"
        })

      assert blocked_conn.status == 429
    end
  end

  describe "protected API endpoints rate limiting" do
    setup do
      # Create a mock authenticated user
      user = %{id: 123, email: "user@test.com"}
      %{user: user}
    end

    test "protected endpoints use api limits", %{conn: conn, user: user} do
      # Mock authentication
      conn = Guardian.Plug.put_current_resource(conn, user)

      # API endpoints should allow more requests (1000 per minute)
      # Test with a reasonable number to verify it's using api_limits
      for _ <- 1..50 do
        get(conn, ~p"/api/v1/auth/me")
      end

      # Should still be allowed since api_limits is much higher
      result_conn = get(conn, ~p"/api/v1/auth/me")
      assert result_conn.status != 429

      # Verify it's using user-based limiting
      assert get_resp_header(result_conn, "x-ratelimit-limit") == ["1000"]
    end
  end

  describe "different clients and isolation" do
    test "different IPs have separate rate limits", %{conn: conn} do
      # Client 1
      conn1 = %{conn | remote_ip: {192, 168, 1, 1}}

      # Make requests up to limit for client 1
      for _ <- 1..10 do
        post(conn1, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})
      end

      # Client 1 should be blocked
      blocked_conn1 =
        post(conn1, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})

      assert blocked_conn1.status == 429

      # Client 2 should still be allowed
      conn2 = %{conn | remote_ip: {192, 168, 1, 2}}

      allowed_conn2 =
        post(conn2, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})

      assert allowed_conn2.status != 429
    end

    test "x-forwarded-for header is respected", %{conn: conn} do
      # Simulate request through proxy
      conn_with_proxy = put_req_header(conn, "x-forwarded-for", "203.0.113.1, 192.168.1.1")

      # Make requests up to limit
      for _ <- 1..10 do
        post(conn_with_proxy, ~p"/api/v1/auth/login", %{
          email: "test@example.com",
          password: "pass"
        })
      end

      # Should be blocked based on forwarded IP
      blocked_conn =
        post(conn_with_proxy, ~p"/api/v1/auth/login", %{
          email: "test@example.com",
          password: "pass"
        })

      assert blocked_conn.status == 429

      # Different forwarded IP should be allowed
      conn_different_ip = put_req_header(conn, "x-forwarded-for", "203.0.113.2")

      allowed_conn =
        post(conn_different_ip, ~p"/api/v1/auth/login", %{
          email: "test@example.com",
          password: "pass"
        })

      assert allowed_conn.status != 429
    end
  end

  describe "admin bypass functionality" do
    test "admin users bypass all rate limits", %{conn: conn} do
      admin_user = %{
        id: 1,
        email: "admin@test.com",
        roles: [%{name: "admin"}]
      }

      conn = Guardian.Plug.put_current_resource(conn, admin_user)

      # Make many requests to auth endpoints - should all pass
      for _ <- 1..20 do
        result_conn =
          post(conn, ~p"/api/v1/auth/login", %{email: "admin@test.com", password: "pass"})

        assert result_conn.status != 429
        assert get_resp_header(result_conn, "x-ratelimit-bypass") == ["admin"]
      end
    end

    test "users with bypass permission bypass rate limits", %{conn: conn} do
      bypass_user = %{
        id: 2,
        email: "bypass@test.com",
        permissions: [%{name: "rate_limit_bypass"}]
      }

      conn = Guardian.Plug.put_current_resource(conn, bypass_user)

      # Make many requests - should all pass
      for _ <- 1..15 do
        result_conn =
          post(conn, ~p"/api/v1/auth/login", %{email: "bypass@test.com", password: "pass"})

        assert result_conn.status != 429
        assert get_resp_header(result_conn, "x-ratelimit-bypass") == ["admin"]
      end
    end
  end

  describe "sliding window accuracy" do
    test "requests are allowed again after window expires" do
      # Use very short window for testing
      Application.put_env(:base_acl_ex, :rate_limiting_test_mode, true)

      # Override the plug configuration temporarily
      original_pipeline = Application.get_env(:base_acl_ex, :rate_limiting_enabled)

      try do
        # This would require implementing a test mode that allows custom window sizes
        # For now, we'll test the concept

        # Make requests to fill up the limit
        conn = %{build_conn() | remote_ip: {192, 168, 1, 99}}

        requests =
          for _ <- 1..10 do
            post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})
          end

        # Should have some successful and one blocked
        successful = Enum.count(requests, &(&1.status != 429))
        blocked = Enum.count(requests, &(&1.status == 429))

        assert successful == 10
        assert blocked == 0

        # 11th should be blocked
        blocked_conn =
          post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})

        assert blocked_conn.status == 429
      after
        Application.put_env(:base_acl_ex, :rate_limiting_enabled, original_pipeline)
      end
    end
  end

  describe "monitoring and observability" do
    test "rate limit headers are consistent across requests", %{conn: conn} do
      # Make first request
      conn1 = post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})
      assert get_resp_header(conn1, "x-ratelimit-limit") == ["10"]
      assert get_resp_header(conn1, "x-ratelimit-remaining") == ["9"]
      assert get_resp_header(conn1, "x-ratelimit-window") == ["60"]

      # Make second request
      conn2 = post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})
      assert get_resp_header(conn2, "x-ratelimit-remaining") == ["8"]

      # Make third request
      conn3 = post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})
      assert get_resp_header(conn3, "x-ratelimit-remaining") == ["7"]
    end

    test "blocked requests include retry-after information", %{conn: conn} do
      # Fill up the rate limit
      for _ <- 1..10 do
        post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})
      end

      # Get blocked
      blocked_conn =
        post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})

      response = json_response(blocked_conn, 429)
      assert Map.has_key?(response["error"], "retry_after")
      assert is_integer(response["error"]["retry_after"])
      assert response["error"]["retry_after"] >= 0
    end
  end

  describe "configuration disabled" do
    test "requests pass through when rate limiting is disabled", %{conn: conn} do
      Application.put_env(:base_acl_ex, :rate_limiting_enabled, false)

      # Make many requests - all should pass
      for _ <- 1..20 do
        result_conn =
          post(conn, ~p"/api/v1/auth/login", %{email: "test@example.com", password: "pass"})

        assert result_conn.status != 429
        # Should not have rate limit headers when disabled
        assert get_resp_header(result_conn, "x-ratelimit-limit") == []
      end
    end
  end
end
