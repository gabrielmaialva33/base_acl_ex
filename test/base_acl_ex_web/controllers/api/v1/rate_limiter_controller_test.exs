defmodule BaseAclExWeb.Api.V1.RateLimiterControllerTest do
  use BaseAclExWeb.ConnCase, async: false

  alias BaseAclEx.Infrastructure.Security.Services.RateLimiter
  alias BaseAclEx.Infrastructure.Security.Services.RateLimiterManager

  @cache_name :rate_limiter_cache

  setup do
    # Ensure cache is clean before each test
    Cachex.clear(@cache_name)
    
    # Create a mock admin user for testing
    admin_user = %{
      id: 1,
      email: "admin@test.com",
      roles: [%{name: "admin"}]
    }
    
    %{admin_user: admin_user}
  end

  describe "GET /api/v1/admin/rate-limiter/stats" do
    test "returns system statistics", %{conn: conn, admin_user: admin_user} do
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/stats")
      
      assert %{
        "data" => %{
          "cache" => cache_stats,
          "config" => config_stats,
          "uptime" => _uptime
        }
      } = json_response(conn, 200)
      
      assert Map.has_key?(cache_stats, "size")
      assert Map.has_key?(config_stats, "enabled")
    end
  end

  describe "GET /api/v1/admin/rate-limiter/limits" do
    test "returns empty list when no active limits", %{conn: conn, admin_user: admin_user} do
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/limits")
      
      assert %{
        "data" => %{
          "limits" => [],
          "total" => 0
        }
      } = json_response(conn, 200)
    end

    test "returns active limits", %{conn: conn, admin_user: admin_user} do
      # Create some rate limits
      RateLimiter.check_rate_limit("192.168.1.1", max_requests: 10)
      RateLimiter.check_rate_limit("192.168.1.2", max_requests: 10)
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/limits")
      
      assert %{
        "data" => %{
          "limits" => limits,
          "total" => 2
        }
      } = json_response(conn, 200)
      
      assert length(limits) == 2
      assert Enum.any?(limits, &(&1["identifier"] == "192.168.1.1"))
    end

    test "filters by pattern", %{conn: conn, admin_user: admin_user} do
      # Create rate limits
      RateLimiter.check_rate_limit("192.168.1.1", max_requests: 10)
      RateLimiter.check_rate_limit("user:123", max_requests: 10)
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/limits?pattern=user:")
      
      assert %{
        "data" => %{
          "limits" => limits,
          "total" => 1
        }
      } = json_response(conn, 200)
      
      assert length(limits) == 1
      assert List.first(limits)["identifier"] == "user:123"
    end

    test "shows only blocked limits", %{conn: conn, admin_user: admin_user} do
      # Create limits, one exceeding threshold
      RateLimiter.check_rate_limit("normal_ip", max_requests: 10)
      
      # Exceed limit for blocked_ip
      for _ <- 1..6 do
        RateLimiter.check_rate_limit("blocked_ip", max_requests: 5)
      end
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/limits?blocked_only=true")
      
      assert %{
        "data" => %{
          "limits" => limits
        }
      } = json_response(conn, 200)
      
      # Should only return the blocked IP
      assert length(limits) == 1
      assert List.first(limits)["identifier"] == "blocked_ip"
      assert List.first(limits)["exceeded"] == true
    end
  end

  describe "GET /api/v1/admin/rate-limiter/limits/:identifier" do
    test "returns limit details for existing identifier", %{conn: conn, admin_user: admin_user} do
      identifier = "test_detail_ip"
      RateLimiter.check_rate_limit(identifier, max_requests: 10)
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/limits/#{identifier}")
      
      assert %{
        "data" => %{
          "identifier" => ^identifier,
          "current_requests" => 1,
          "max_requests" => 10,
          "remaining" => 9,
          "exceeded" => false
        }
      } = json_response(conn, 200)
    end

    test "returns 404 for non-existent identifier", %{conn: conn, admin_user: admin_user} do
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/limits/nonexistent")
      
      assert %{
        "error" => %{
          "type" => "not_found"
        }
      } = json_response(conn, 404)
    end
  end

  describe "DELETE /api/v1/admin/rate-limiter/limits/:identifier" do
    test "removes specific rate limit", %{conn: conn, admin_user: admin_user} do
      identifier = "test_remove_ip"
      RateLimiter.check_rate_limit(identifier, max_requests: 10)
      RateLimiter.check_rate_limit(identifier, max_requests: 10)
      
      # Verify limit exists
      assert {:ok, _} = RateLimiterManager.get_limit_details(identifier)
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = delete(conn, ~p"/api/v1/admin/rate-limiter/limits/#{identifier}")
      
      assert json_response(conn, 200)
      
      # Verify limit is removed
      assert {:error, :not_found} = RateLimiterManager.get_limit_details(identifier)
    end
  end

  describe "DELETE /api/v1/admin/rate-limiter/limits" do
    test "requires confirmation", %{conn: conn, admin_user: admin_user} do
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = delete(conn, ~p"/api/v1/admin/rate-limiter/limits")
      
      assert %{
        "error" => %{
          "type" => "confirmation_required"
        }
      } = json_response(conn, 400)
    end

    test "clears all limits with confirmation", %{conn: conn, admin_user: admin_user} do
      # Create some limits
      RateLimiter.check_rate_limit("ip1", max_requests: 10)
      RateLimiter.check_rate_limit("ip2", max_requests: 10)
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = delete(conn, ~p"/api/v1/admin/rate-limiter/limits?confirm=yes")
      
      assert json_response(conn, 200)
      
      # Verify all limits are cleared
      assert RateLimiterManager.list_active_limits() == []
    end
  end

  describe "GET /api/v1/admin/rate-limiter/export" do
    test "exports data in JSON format", %{conn: conn, admin_user: admin_user} do
      # Create some test data
      RateLimiter.check_rate_limit("export_test_ip", max_requests: 5)
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/export")
      
      assert response = json_response(conn, 200)
      assert Map.has_key?(response, "exported_at")
      assert Map.has_key?(response, "limits")
      assert is_list(response["limits"])
    end

    test "exports data in CSV format", %{conn: conn, admin_user: admin_user} do
      # Create some test data
      RateLimiter.check_rate_limit("csv_test_ip", max_requests: 5)
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = get(conn, ~p"/api/v1/admin/rate-limiter/export?format=csv")
      
      assert response(conn, 200)
      assert get_resp_header(conn, "content-type") == ["text/csv"]
      assert get_resp_header(conn, "content-disposition") |> List.first() =~ "attachment"
    end
  end

  describe "POST /api/v1/admin/rate-limiter/test" do
    test "tests rate limit without affecting real limits", %{conn: conn, admin_user: admin_user} do
      test_params = %{
        "identifier" => "test_identifier",
        "max_requests" => "5",
        "window_ms" => "60000"
      }
      
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = post(conn, ~p"/api/v1/admin/rate-limiter/test", test_params)
      
      assert %{
        "data" => %{
          "identifier" => "test_identifier",
          "current_requests" => 0,
          "max_requests" => 5,
          "remaining" => 5,
          "exceeded" => false
        }
      } = json_response(conn, 200)
    end

    test "requires identifier parameter", %{conn: conn, admin_user: admin_user} do
      conn = Guardian.Plug.put_current_resource(conn, admin_user)
      conn = post(conn, ~p"/api/v1/admin/rate-limiter/test", %{})
      
      assert %{
        "error" => %{
          "type" => "missing_parameter"
        }
      } = json_response(conn, 400)
    end
  end
end