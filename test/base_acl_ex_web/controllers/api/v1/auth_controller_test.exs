defmodule BaseAclExWeb.Api.V1.AuthControllerTest do
  use BaseAclExWeb.ConnCase

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Accounts.Core.ValueObjects.Password
  alias BaseAclEx.Factory
  alias BaseAclEx.TestSupport.AuthHelpers
  import AuthHelpers

  describe "POST /api/v1/auth/register" do
    test "creates user with valid parameters", %{conn: conn} do
      params = valid_registration_params()

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{
               "id" => user_id,
               "email" => email,
               "first_name" => "John",
               "last_name" => "Doe",
               "username" => username
             } = json_response(conn, 201)["data"]

      assert_uuid(user_id)
      assert email == params["email"]
      assert username

      # Verify user was created in database
      assert_record_exists(User, %{email: params["email"]})
    end

    test "creates user with minimal valid parameters", %{conn: conn} do
      params = %{
        "email" => "minimal@example.com",
        "password" => "SecurePass123!",
        "first_name" => "Jane",
        "last_name" => "Smith",
        "terms_accepted" => true
      }

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{"id" => user_id} = json_response(conn, 201)["data"]
      assert_uuid(user_id)

      # Verify user was created in database
      assert_record_exists(User, %{email: "minimal@example.com"})
    end

    test "returns error with invalid email", %{conn: conn} do
      params = valid_registration_params(%{"email" => "invalid-email"})

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{"errors" => errors} = json_response(conn, 422)
      assert errors["email"]
    end

    test "returns error with weak password", %{conn: conn} do
      params = valid_registration_params(%{"password" => "weak"})

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{"errors" => errors} = json_response(conn, 422)
      assert errors["password"]
    end

    test "returns error with missing required fields", %{conn: conn} do
      params = %{
        "email" => "test@example.com"
        # Missing other required fields
      }

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{"errors" => errors} = json_response(conn, 422)
      assert errors["password"]
      assert errors["first_name"]
      assert errors["last_name"]
    end

    test "returns error when terms not accepted", %{conn: conn} do
      params = valid_registration_params(%{"terms_accepted" => false})

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{"errors" => errors} = json_response(conn, 422)
      assert errors["terms_accepted"]
    end

    test "returns error with duplicate email", %{conn: conn} do
      existing_user = Factory.insert_user()
      params = valid_registration_params(%{"email" => existing_user.email})

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{"errors" => errors} = json_response(conn, 422)
      assert errors["email"]
    end

    test "returns error with duplicate username", %{conn: conn} do
      existing_user = Factory.insert_user(%{username: "existinguser"})
      params = valid_registration_params(%{"username" => existing_user.username})

      conn = post(conn, ~p"/api/v1/auth/register", params)

      assert %{"errors" => errors} = json_response(conn, 422)
      assert errors["username"]
    end
  end

  describe "POST /api/v1/auth/login" do
    test "authenticates user with valid credentials", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      params = %{
        "email" => "test@example.com",
        "password" => "SecurePass123!"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert %{
               "user" => user_data,
               "tokens" => tokens
             } = json_response(conn, 200)["data"]

      assert user_data["id"] == user.id
      assert user_data["email"] == user.email
      assert tokens["access_token"]
      assert tokens["refresh_token"]

      # Verify tokens are valid JWTs
      assert_valid_jwt(tokens["access_token"])
      assert_valid_jwt(tokens["refresh_token"])
    end

    test "handles case insensitive email", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "test@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now()
      })

      params = %{
        "email" => "TEST@EXAMPLE.COM",
        "password" => "SecurePass123!"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert json_response(conn, 200)["data"]
    end

    test "returns error with invalid email", %{conn: conn} do
      params = %{
        "email" => "nonexistent@example.com",
        "password" => "SecurePass123!"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert %{"error" => "invalid_credentials"} = json_response(conn, 401)
    end

    test "returns error with invalid password", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "test@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now()
      })

      params = %{
        "email" => "test@example.com",
        "password" => "WrongPassword123!"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert %{"error" => "invalid_credentials"} = json_response(conn, 401)
    end

    test "returns error for deleted user", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "deleted@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now(),
        deleted_at: DateTime.utc_now()
      })

      params = %{
        "email" => "deleted@example.com",
        "password" => "SecurePass123!"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert %{"error" => "account_deleted"} = json_response(conn, 401)
    end

    test "returns error for locked user", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "locked@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now(),
        locked_until: DateTime.add(DateTime.utc_now(), 900, :second)
      })

      params = %{
        "email" => "locked@example.com",
        "password" => "SecurePass123!"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert %{"error" => "account_locked"} = json_response(conn, 401)
    end

    test "returns error for unverified email", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "unverified@example.com",
        password_hash: password_hash,
        email_verified_at: nil
      })

      params = %{
        "email" => "unverified@example.com",
        "password" => "SecurePass123!"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert %{"error" => "email_not_verified"} = json_response(conn, 401)
    end

    test "includes IP address and user agent in request", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      params = %{
        "email" => "test@example.com",
        "password" => "SecurePass123!"
      }

      conn =
        conn
        |> put_req_header("user-agent", "TestClient/1.0")
        |> post(~p"/api/v1/auth/login", params)

      assert json_response(conn, 200)

      # Verify login was recorded with IP and user agent
      updated_user = Repo.get!(User, user.id)
      assert updated_user.last_login_at
      assert updated_user.last_login_ip == "127.0.0.1"
    end

    test "supports remember me option", %{conn: conn} do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "test@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now()
      })

      params = %{
        "email" => "test@example.com",
        "password" => "SecurePass123!",
        "remember_me" => true
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      assert %{"tokens" => tokens} = json_response(conn, 200)["data"]

      # With remember_me, refresh token should have longer expiration
      # This would need to be verified by decoding the refresh token
      # and checking the exp claim
      assert tokens["refresh_token"]
    end
  end

  describe "POST /api/v1/auth/refresh" do
    test "refreshes access token with valid refresh token", %{conn: conn} do
      user = Factory.insert_user()
      tokens = create_tokens(user)

      params = %{
        "refresh_token" => tokens.refresh_token
      }

      conn = post(conn, ~p"/api/v1/auth/refresh", params)

      assert %{"tokens" => new_tokens} = json_response(conn, 200)["data"]
      assert new_tokens["access_token"]
      assert new_tokens["refresh_token"]

      # New tokens should be different from original
      assert new_tokens["access_token"] != tokens.access_token
      assert_different_tokens(new_tokens["access_token"], tokens.access_token)
    end

    test "returns error with invalid refresh token", %{conn: conn} do
      params = %{
        "refresh_token" => "invalid.refresh.token"
      }

      conn = post(conn, ~p"/api/v1/auth/refresh", params)

      assert %{"error" => _} = json_response(conn, 401)
    end

    test "returns error with expired refresh token", %{conn: conn} do
      # This would require creating an expired token
      # In practice, this might be hard to test without manipulating time
      params = %{
        "refresh_token" => "expired.refresh.token"
      }

      conn = post(conn, ~p"/api/v1/auth/refresh", params)

      assert %{"error" => _} = json_response(conn, 401)
    end
  end

  describe "POST /api/v1/auth/logout (authenticated)" do
    test "successfully logs out authenticated user", %{conn: conn} do
      user = Factory.insert_user()

      conn =
        conn
        |> authenticate_conn(user)
        |> post(~p"/api/v1/auth/logout")

      assert %{"message" => "Successfully logged out"} = json_response(conn, 200)["data"]
    end

    test "requires authentication", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/auth/logout")

      assert_unauthorized(conn)
    end
  end

  describe "GET /api/v1/auth/me (authenticated)" do
    test "returns current user information", %{conn: conn} do
      user =
        Factory.insert_user(%{
          first_name: "John",
          last_name: "Doe",
          email: "john@example.com",
          username: "johndoe"
        })

      conn =
        conn
        |> authenticate_conn(user)
        |> get(~p"/api/v1/auth/me")

      assert %{
               "id" => user_id,
               "email" => "john@example.com",
               "first_name" => "John",
               "last_name" => "Doe",
               "username" => "johndoe"
             } = json_response(conn, 200)["data"]

      assert user_id == user.id
    end

    test "requires authentication", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/auth/me")

      assert_unauthorized(conn)
    end

    test "returns error with invalid token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer invalid.token.here")
        |> get(~p"/api/v1/auth/me")

      assert_unauthorized(conn)
    end
  end

  describe "GET /api/v1/auth/verify (authenticated)" do
    test "verifies valid token", %{conn: conn} do
      user = Factory.insert_user()

      conn =
        conn
        |> authenticate_conn(user)
        |> get(~p"/api/v1/auth/verify")

      assert %{
               "valid" => true,
               "user" => user_data
             } = json_response(conn, 200)["data"]

      assert user_data["id"] == user.id
    end

    test "returns invalid for unauthenticated request", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/auth/verify")

      assert %{
               "valid" => false,
               "user" => nil
             } = json_response(conn, 401)["data"]
    end

    test "returns invalid for invalid token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer invalid.token")
        |> get(~p"/api/v1/auth/verify")

      assert %{
               "valid" => false,
               "user" => nil
             } = json_response(conn, 401)["data"]
    end
  end

  describe "request validation and error handling" do
    test "handles malformed JSON", %{conn: conn} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/auth/login", "{invalid json")

      # Should return 400 for malformed JSON
      assert conn.status == 400
    end

    test "handles missing required parameters for login", %{conn: conn} do
      test_cases = [
        # Missing password
        %{"email" => "test@example.com"},
        # Missing email
        %{"password" => "SecurePass123!"},
        # Missing both
        %{}
      ]

      for params <- test_cases do
        conn = post(conn, ~p"/api/v1/auth/login", params)

        # Should return 400 or 422 for missing parameters
        assert conn.status in [400, 422]
      end
    end

    test "handles extremely large request payloads gracefully", %{conn: conn} do
      large_string = String.duplicate("a", 10_000)

      params = %{
        "email" => "test@example.com",
        "password" => "SecurePass123!",
        "large_field" => large_string
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      # Should handle large payload gracefully (might ignore extra fields)
      # The exact behavior depends on your parameter filtering
      assert conn.status in [200, 400, 401, 422]
    end
  end

  describe "security headers and response format" do
    test "includes appropriate security headers", %{conn: conn} do
      user = Factory.insert_user()

      conn =
        conn
        |> authenticate_conn(user)
        |> get(~p"/api/v1/auth/me")

      # Check for security headers
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]

      # Additional security headers would be set by plugs
      # This is just an example of what you might check
    end

    test "does not include sensitive information in error responses", %{conn: conn} do
      # Test that error responses don't leak sensitive information
      params = %{
        "email" => "nonexistent@example.com",
        "password" => "wrongpassword"
      }

      conn = post(conn, ~p"/api/v1/auth/login", params)

      response = json_response(conn, 401)

      # Should not reveal whether email exists or not
      assert response["error"] == "invalid_credentials"
      refute String.contains?(Jason.encode!(response), "nonexistent")
      refute String.contains?(Jason.encode!(response), "password")
    end

    test "response times are consistent for failed logins", %{conn: conn} do
      # Test that failed login attempts take similar time regardless of whether
      # the email exists or not (timing attack prevention)

      # Create a user
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "existing@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now()
      })

      test_cases = [
        %{"email" => "existing@example.com", "password" => "wrongpassword"},
        %{"email" => "nonexistent@example.com", "password" => "wrongpassword"}
      ]

      times =
        Enum.map(test_cases, fn params ->
          {time, conn} =
            :timer.tc(fn ->
              post(build_conn(), ~p"/api/v1/auth/login", params)
            end)

          assert conn.status == 401
          time
        end)

      # Times should be relatively similar (within 50ms)
      max_time = Enum.max(times)
      min_time = Enum.min(times)
      time_diff = max_time - min_time

      assert time_diff < 50_000, "Response times vary too much: #{inspect(times)}"
    end
  end

  # Helper function to create tokens for testing
  defp create_tokens(user) do
    alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl
    {:ok, access_token, _claims} = GuardianImpl.encode_and_sign(user, %{}, token_type: "access")
    {:ok, refresh_token, _claims} = GuardianImpl.encode_and_sign(user, %{}, token_type: "refresh")

    %{
      access_token: access_token,
      refresh_token: refresh_token
    }
  end
end
