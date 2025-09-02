defmodule BaseAclEx.Accounts.Application.Handlers.AuthenticateUserHandlerTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Accounts.Application.Commands.AuthenticateUserCommand
  alias BaseAclEx.Accounts.Application.Handlers.AuthenticateUserHandler
  alias BaseAclEx.Accounts.Core.ValueObjects.Password
  alias BaseAclEx.Factory
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  describe "execute/1" do
    test "successfully authenticates user with valid credentials" do
      # Create user with known password
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:ok, result} = AuthenticateUserHandler.execute(command)

      # Verify result structure
      assert result.user.id == user.id
      assert result.user.email == user.email
      assert result.tokens
      assert result.tokens.access_token
      assert result.tokens.refresh_token
      assert result.domain_events

      # Verify domain event
      assert_domain_event(result.domain_events, "user_authenticated")

      event = Enum.find(result.domain_events, &(&1.type == "user_authenticated"))
      assert event.aggregate_id == user.id
      assert event.payload.user_id == user.id
      assert event.payload.email == user.email
      assert event.payload.ip_address == "192.168.1.1"
      assert event.payload.user_agent == "TestAgent/1.0"
    end

    test "fails with invalid email" do
      command = %AuthenticateUserCommand{
        email: "nonexistent@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:error, :invalid_credentials} = AuthenticateUserHandler.execute(command)
    end

    test "fails with incorrect password" do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "test@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now()
      })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "WrongPassword123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:error, :invalid_credentials} = AuthenticateUserHandler.execute(command)
    end

    test "fails with deleted user account" do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "test@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now(),
        deleted_at: DateTime.utc_now()
      })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:error, :account_deleted} = AuthenticateUserHandler.execute(command)
    end

    test "fails with locked user account" do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "test@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now(),
        locked_until: DateTime.add(DateTime.utc_now(), 900, :second)
      })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:error, :account_locked} = AuthenticateUserHandler.execute(command)
    end

    test "fails with unverified email" do
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "test@example.com",
        password_hash: password_hash,
        # Unverified email
        email_verified_at: nil
      })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:error, :email_not_verified} = AuthenticateUserHandler.execute(command)
    end

    test "is case insensitive for email" do
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      command = %AuthenticateUserCommand{
        # Different case
        email: "TEST@EXAMPLE.COM",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:ok, result} = AuthenticateUserHandler.execute(command)
      assert result.user.id == user.id
    end

    test "records login information in database" do
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now(),
          last_login_at: nil,
          login_count: 0
        })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      {:ok, _result} = AuthenticateUserHandler.execute(command)

      # Verify database was updated
      updated_user = Repo.get!(BaseAclEx.Accounts.Core.Entities.User, user.id)
      assert updated_user.last_login_at
      assert_recent_datetime(updated_user.last_login_at)
      assert updated_user.login_count == 1
      assert updated_user.last_login_ip == "192.168.1.1"
    end

    test "handles user with existing login history" do
      password_hash = Password.hash_password("SecurePass123!")
      past_login = DateTime.add(DateTime.utc_now(), -3600, :second)

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now(),
          last_login_at: past_login,
          login_count: 5,
          last_login_ip: "192.168.1.100"
        })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.200",
        user_agent: "TestAgent/1.0"
      }

      {:ok, _result} = AuthenticateUserHandler.execute(command)

      # Verify database was updated correctly
      updated_user = Repo.get!(BaseAclEx.Accounts.Core.Entities.User, user.id)
      assert DateTime.compare(updated_user.last_login_at, past_login) == :gt
      assert updated_user.login_count == 6
      assert updated_user.last_login_ip == "192.168.1.200"
    end
  end

  describe "token generation" do
    test "generates valid JWT tokens" do
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      {:ok, result} = AuthenticateUserHandler.execute(command)

      # Verify token structure
      assert is_binary(result.tokens.access_token)
      assert is_binary(result.tokens.refresh_token)
      assert String.length(result.tokens.access_token) > 100
      assert String.length(result.tokens.refresh_token) > 100

      # Verify tokens are different
      refute result.tokens.access_token == result.tokens.refresh_token

      # Verify tokens can be decoded (basic JWT structure test)
      alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl
      assert {:ok, claims} = GuardianImpl.decode_and_verify(result.tokens.access_token)
      assert claims["sub"] == user.id
    end

    test "tokens contain correct user information" do
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      {:ok, result} = AuthenticateUserHandler.execute(command)

      # Decode and verify token claims
      alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl
      {:ok, claims} = GuardianImpl.decode_and_verify(result.tokens.access_token)

      assert claims["sub"] == user.id
      assert claims["email"] == user.email
      assert claims["typ"] == "access"
      assert claims["exp"]
      assert claims["iat"]
    end
  end

  describe "edge cases and error handling" do
    test "handles malformed command gracefully" do
      # Test with nil command - this would be caught by pattern matching
      # but we can test edge cases within valid command structure

      command = %AuthenticateUserCommand{
        email: nil,
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      # Should fail at the user lookup stage
      assert {:error, :invalid_credentials} = AuthenticateUserHandler.execute(command)
    end

    test "handles database errors gracefully" do
      # This is harder to test without mocking, but we can test with
      # malformed data that might cause issues

      command = %AuthenticateUserCommand{
        # Empty email
        email: "",
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      assert {:error, :invalid_credentials} = AuthenticateUserHandler.execute(command)
    end

    test "handles very long email addresses" do
      # Test with maximum length email
      long_email = String.duplicate("a", 64) <> "@" <> String.duplicate("b", 187) <> ".com"
      password_hash = Password.hash_password("SecurePass123!")

      user =
        Factory.insert_user(%{
          email: long_email,
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      command = %AuthenticateUserCommand{
        email: long_email,
        password: "SecurePass123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      {:ok, result} = AuthenticateUserHandler.execute(command)
      assert result.user.id == user.id
    end

    test "handles special characters in password" do
      special_password = "P@$$w0rd!@#$%^&*()_+-=[]{}|;':\",./<>?"
      password_hash = Password.hash_password(special_password)

      user =
        Factory.insert_user(%{
          email: "test@example.com",
          password_hash: password_hash,
          email_verified_at: DateTime.utc_now()
        })

      command = %AuthenticateUserCommand{
        email: "test@example.com",
        password: special_password,
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      {:ok, result} = AuthenticateUserHandler.execute(command)
      assert result.user.id == user.id
    end
  end

  describe "security considerations" do
    test "does not reveal whether email exists for invalid password" do
      # Both scenarios should return the same error
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "existing@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now()
      })

      # Existing user, wrong password
      command1 = %AuthenticateUserCommand{
        email: "existing@example.com",
        password: "WrongPassword123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      # Non-existing user
      command2 = %AuthenticateUserCommand{
        email: "nonexistent@example.com",
        password: "AnyPassword123!",
        ip_address: "192.168.1.1",
        user_agent: "TestAgent/1.0"
      }

      # Both should return the same generic error
      assert {:error, :invalid_credentials} = AuthenticateUserHandler.execute(command1)
      assert {:error, :invalid_credentials} = AuthenticateUserHandler.execute(command2)
    end

    test "timing attack resistance - consistent response times" do
      # This test would ideally measure timing, but for unit tests we'll
      # just verify the same code path is taken for both scenarios
      password_hash = Password.hash_password("SecurePass123!")

      Factory.insert_user(%{
        email: "existing@example.com",
        password_hash: password_hash,
        email_verified_at: DateTime.utc_now()
      })

      # The handler should perform the same password verification steps
      # regardless of whether the user exists, to prevent timing attacks

      commands = [
        %AuthenticateUserCommand{
          email: "existing@example.com",
          password: "WrongPassword123!",
          ip_address: "192.168.1.1",
          user_agent: "TestAgent/1.0"
        },
        %AuthenticateUserCommand{
          email: "nonexistent@example.com",
          password: "WrongPassword123!",
          ip_address: "192.168.1.1",
          user_agent: "TestAgent/1.0"
        }
      ]

      # Both should return the same error in similar time
      results =
        Enum.map(commands, fn command ->
          {time, result} = :timer.tc(fn -> AuthenticateUserHandler.execute(command) end)
          {time, result}
        end)

      # All should fail with same error
      Enum.each(results, fn {_time, result} ->
        assert {:error, :invalid_credentials} = result
      end)

      # Times should be relatively similar (within 50ms of each other)
      # This is a basic check - in production you'd want more sophisticated timing analysis
      times = Enum.map(results, fn {time, _} -> time end)
      max_time = Enum.max(times)
      min_time = Enum.min(times)
      time_diff = max_time - min_time

      # Should be within 50,000 microseconds (50ms) of each other
      assert time_diff < 50_000, "Response times differ by more than 50ms: #{inspect(times)}"
    end
  end
end
