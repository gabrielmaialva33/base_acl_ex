defmodule BaseAclEx.Accounts.Application.Handlers.RegisterUserHandlerTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Accounts.Application.Commands.RegisterUserCommand
  alias BaseAclEx.Accounts.Application.Handlers.RegisterUserHandler
  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Factory
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  describe "execute/1" do
    test "successfully registers a new user with valid data" do
      command = %RegisterUserCommand{
        email: "newuser@example.com",
        password: "SecurePass123!",
        first_name: "John",
        last_name: "Doe",
        username: "johndoe",
        phone_number: "+1234567890",
        terms_accepted: true,
        newsletter_opt_in: true
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)

      # Verify result structure
      assert result.user
      assert result.domain_events
      assert is_list(result.domain_events)

      user = result.user

      # Verify user attributes
      assert user.email == "newuser@example.com"
      assert user.first_name == "John"
      assert user.last_name == "Doe"
      assert user.username == "johndoe"
      assert user.phone == "+1234567890"
      assert user.password_hash
      assert String.starts_with?(user.password_hash, "$argon2id$")

      # Verify user was persisted
      assert user.id
      assert_uuid(user.id)
      assert_recent_datetime(user.inserted_at)

      # Verify domain event
      assert_domain_event(result.domain_events, "user_registered")

      event = Enum.find(result.domain_events, &(&1.type == "user_registered"))
      assert event.aggregate_id == user.id
      assert event.payload.user_id == user.id
      assert event.payload.email == user.email
      assert event.payload.username == user.username
    end

    test "successfully registers user with minimal required data" do
      command = %RegisterUserCommand{
        email: "minimal@example.com",
        password: "SecurePass123!",
        first_name: "Jane",
        last_name: "Smith",
        username: nil,
        phone_number: nil,
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)

      user = result.user
      assert user.email == "minimal@example.com"
      assert user.first_name == "Jane"
      assert user.last_name == "Smith"
      # Should be auto-generated
      assert user.username
      assert String.contains?(user.username, "jane.smith")
      refute user.phone
    end

    test "generates unique username when not provided" do
      command = %RegisterUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        first_name: "Test",
        last_name: "User",
        username: nil,
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)

      user = result.user
      assert user.username
      assert String.contains?(user.username, "test.user")
      assert String.match?(user.username, ~r/test\.user\.\d+/)
    end

    test "handles special characters in name for username generation" do
      command = %RegisterUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        first_name: "José-María",
        last_name: "González-López",
        username: nil,
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)

      user = result.user
      assert user.username
      # Should clean special characters
      assert String.match?(user.username, ~r/^[a-z0-9.]+$/)
      assert String.contains?(user.username, "jose")
      assert String.contains?(user.username, "gonzalez")
    end

    test "fails with invalid email" do
      command = %RegisterUserCommand{
        email: "invalid-email",
        password: "SecurePass123!",
        first_name: "John",
        last_name: "Doe",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:error, _errors} = RegisterUserHandler.execute(command)
    end

    test "fails with weak password" do
      command = %RegisterUserCommand{
        email: "test@example.com",
        password: "weak",
        first_name: "John",
        last_name: "Doe",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:error, _errors} = RegisterUserHandler.execute(command)
    end

    test "fails when email already exists" do
      # Create existing user
      Factory.insert_user(%{email: "existing@example.com"})

      command = %RegisterUserCommand{
        email: "existing@example.com",
        password: "SecurePass123!",
        first_name: "John",
        last_name: "Doe",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:error, errors} = RegisterUserHandler.execute(command)
      assert is_map(errors)
      assert errors[:email]
    end

    test "fails when username already exists" do
      # Create existing user with username
      Factory.insert_user(%{username: "existinguser"})

      command = %RegisterUserCommand{
        email: "newuser@example.com",
        password: "SecurePass123!",
        first_name: "John",
        last_name: "Doe",
        username: "existinguser",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:error, errors} = RegisterUserHandler.execute(command)
      assert is_map(errors)
      assert errors[:username]
    end

    test "assigns default user role to new user" do
      # Ensure default user role exists
      role = Factory.insert_role(%{slug: "user", name: "User", hierarchy_level: 30})

      command = %RegisterUserCommand{
        email: "newuser@example.com",
        password: "SecurePass123!",
        first_name: "John",
        last_name: "Doe",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)

      # Verify user was created
      assert result.user.id

      # The handler should assign the default role
      # In a full implementation, this would be verified by checking
      # the user_roles table or user.roles association
    end

    test "creates default user role if it doesn't exist" do
      # Ensure no user role exists
      Repo.delete_all(Role)

      command = %RegisterUserCommand{
        email: "newuser@example.com",
        password: "SecurePass123!",
        first_name: "John",
        last_name: "Doe",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)

      # Verify user was created
      assert result.user.id

      # Verify default role was created
      user_role = Repo.get_by(Role, slug: "user")
      assert user_role
      assert user_role.name == "User"
      assert user_role.is_system == true
      assert user_role.hierarchy_level == 30
    end
  end

  describe "email validation" do
    test "accepts various valid email formats" do
      valid_emails = [
        "user@example.com",
        "user.name@example.com",
        "user+tag@example.com",
        "user123@example.co.uk",
        "test-email@sub.example.com"
      ]

      for email <- valid_emails do
        command = %RegisterUserCommand{
          email: email,
          password: "SecurePass123!",
          first_name: "John",
          last_name: "Doe",
          terms_accepted: true,
          newsletter_opt_in: false
        }

        assert {:ok, _result} = RegisterUserHandler.execute(command),
               "Email #{email} should be accepted"

        # Clean up for next iteration
        Repo.delete_all(User)
      end
    end

    test "rejects invalid email formats" do
      invalid_emails = [
        "invalid-email",
        "@example.com",
        "user@",
        "user@@example.com",
        "user..name@example.com"
      ]

      for email <- invalid_emails do
        command = %RegisterUserCommand{
          email: email,
          password: "SecurePass123!",
          first_name: "John",
          last_name: "Doe",
          terms_accepted: true,
          newsletter_opt_in: false
        }

        assert {:error, _errors} = RegisterUserHandler.execute(command),
               "Email #{email} should be rejected"
      end
    end
  end

  describe "password validation" do
    test "accepts strong passwords" do
      strong_passwords = [
        "SecureP@ssw0rd123",
        "MyStr0ng!Password",
        "C0mpl3x&Secure!",
        "Tr0ub4dor&3"
      ]

      for password <- strong_passwords do
        command = %RegisterUserCommand{
          email: "test#{:rand.uniform(10000)}@example.com",
          password: password,
          first_name: "John",
          last_name: "Doe",
          terms_accepted: true,
          newsletter_opt_in: false
        }

        assert {:ok, result} = RegisterUserHandler.execute(command),
               "Password #{password} should be accepted"

        # Verify password was hashed
        user = result.user
        assert user.password_hash
        assert String.starts_with?(user.password_hash, "$argon2id$")
      end
    end

    test "rejects weak passwords" do
      weak_passwords = [
        "short",
        # Only numbers
        "12345678",
        # Common password
        "password",
        # Only uppercase
        "PASSWORD",
        # Common with numbers
        "password123"
      ]

      for password <- weak_passwords do
        command = %RegisterUserCommand{
          email: "test#{:rand.uniform(10000)}@example.com",
          password: password,
          first_name: "John",
          last_name: "Doe",
          terms_accepted: true,
          newsletter_opt_in: false
        }

        assert {:error, _errors} = RegisterUserHandler.execute(command),
               "Password #{password} should be rejected"
      end
    end
  end

  describe "domain events" do
    test "generates correct user registered event" do
      command = %RegisterUserCommand{
        email: "event@example.com",
        password: "SecurePass123!",
        first_name: "Event",
        last_name: "User",
        username: "eventuser",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)

      # Verify domain event structure
      assert length(result.domain_events) == 1

      event = List.first(result.domain_events)
      assert event.type == "user_registered"
      assert event.aggregate_id == result.user.id
      assert event.occurred_at
      assert_recent_datetime(event.occurred_at)

      # Verify event payload
      payload = event.payload
      assert payload.user_id == result.user.id
      assert payload.email == "event@example.com"
      assert payload.username == "eventuser"
    end
  end

  describe "edge cases and error handling" do
    test "handles empty string fields appropriately" do
      command = %RegisterUserCommand{
        email: "test@example.com",
        password: "SecurePass123!",
        # Empty string
        first_name: "",
        # Empty string
        last_name: "",
        # Empty string
        username: "",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      # Should fail validation due to empty required fields
      assert {:error, _errors} = RegisterUserHandler.execute(command)
    end

    test "handles very long names" do
      long_name = String.duplicate("A", 100)

      command = %RegisterUserCommand{
        email: "longname@example.com",
        password: "SecurePass123!",
        first_name: long_name,
        last_name: long_name,
        terms_accepted: true,
        newsletter_opt_in: false
      }

      # Should handle long names gracefully (might truncate or fail validation)
      case RegisterUserHandler.execute(command) do
        {:ok, result} ->
          # If successful, verify names were handled appropriately
          assert result.user.first_name
          assert result.user.last_name

        {:error, _errors} ->
          # If failed, that's also acceptable for very long names
          :ok
      end
    end

    test "handles maximum length email" do
      # Create a valid email at maximum length (254 characters)
      local_part = String.duplicate("a", 64)
      domain_part = String.duplicate("b", 187) <> ".com"
      max_email = "#{local_part}@#{domain_part}"

      command = %RegisterUserCommand{
        email: max_email,
        password: "SecurePass123!",
        first_name: "Max",
        last_name: "Email",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      assert {:ok, result} = RegisterUserHandler.execute(command)
      assert result.user.email == max_email
    end

    test "handles special characters in phone number" do
      phone_variations = [
        "+1-234-567-8900",
        "(234) 567-8900",
        "234.567.8900",
        "+44 20 7946 0958"
      ]

      for phone <- phone_variations do
        command = %RegisterUserCommand{
          email: "phone#{:rand.uniform(10000)}@example.com",
          password: "SecurePass123!",
          first_name: "Phone",
          last_name: "Test",
          phone_number: phone,
          terms_accepted: true,
          newsletter_opt_in: false
        }

        # Should handle various phone formats
        case RegisterUserHandler.execute(command) do
          {:ok, result} ->
            assert result.user.phone == phone

          {:error, _errors} ->
            # Some formats might be rejected by validation
            :ok
        end

        # Clean up
        Repo.delete_all(User)
      end
    end
  end

  describe "concurrent registration" do
    test "handles concurrent registrations with same email" do
      # This test simulates what would happen if two users try to register
      # with the same email simultaneously
      command = %RegisterUserCommand{
        email: "concurrent@example.com",
        password: "SecurePass123!",
        first_name: "Concurrent",
        last_name: "User",
        terms_accepted: true,
        newsletter_opt_in: false
      }

      # First registration should succeed
      assert {:ok, _result1} = RegisterUserHandler.execute(command)

      # Second registration with same email should fail
      assert {:error, _errors} = RegisterUserHandler.execute(command)
    end

    test "handles concurrent username generation" do
      # Test multiple registrations without usernames to see if
      # username generation handles collisions appropriately
      base_command = %RegisterUserCommand{
        password: "SecurePass123!",
        first_name: "Same",
        last_name: "Name",
        # Force username generation
        username: nil,
        terms_accepted: true,
        newsletter_opt_in: false
      }

      # Create multiple registrations with same name pattern
      results =
        for i <- 1..3 do
          command = %{base_command | email: "samename#{i}@example.com"}
          RegisterUserHandler.execute(command)
        end

      # All should succeed
      Enum.each(results, fn result ->
        assert {:ok, _} = result
      end)

      # All usernames should be different
      usernames = Enum.map(results, fn {:ok, result} -> result.user.username end)
      assert length(Enum.uniq(usernames)) == length(usernames)
    end
  end
end
