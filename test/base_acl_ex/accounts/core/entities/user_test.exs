defmodule BaseAclEx.Accounts.Core.Entities.UserTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Factory
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  describe "new/1" do
    test "creates a valid user with required fields" do
      attrs = %{
        email: "test@example.com",
        password: "SecurePass123!",
        first_name: "John",
        last_name: "Doe"
      }

      changeset = User.new(attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.email == "test@example.com"
      assert changeset.changes.first_name == "John"
      assert changeset.changes.last_name == "Doe"
      assert changeset.changes.password_hash
      refute Map.has_key?(changeset.changes, :password)
    end

    test "validates email format" do
      attrs = %{email: "invalid-email", password: "SecurePass123!"}
      changeset = User.new(attrs)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :email, "must have the @ sign and no spaces")
    end

    test "validates email uniqueness" do
      existing_user = Factory.insert_user()

      attrs = %{
        email: existing_user.email,
        password: "SecurePass123!"
      }

      assert_raise Ecto.ConstraintError, fn ->
        User.new(attrs) |> Repo.insert!()
      end
    end

    test "validates password complexity" do
      test_cases = [
        {"short", "Password must be at least 8 characters"},
        {"nouppercase123!", "must contain at least one uppercase letter"},
        {"NOLOWERCASE123!", "must contain at least one lowercase letter"},
        {"NoNumbers!", "must contain at least one number"},
        {"NoSpecialChar123", "must contain at least one special character"}
      ]

      for {password, expected_error} do
        attrs = %{email: "test@example.com", password: password}
        changeset = User.new(attrs)

        assert_changeset_invalid(changeset)
        assert_changeset_error(changeset, :password, ~r/#{expected_error}/i)
      end
    end

    test "validates username format" do
      attrs = %{
        email: "test@example.com",
        password: "SecurePass123!",
        username: "invalid username!"
      }

      changeset = User.new(attrs)

      assert_changeset_invalid(changeset)

      assert_changeset_error(
        changeset,
        :username,
        "only letters, numbers, underscore and hyphen allowed"
      )
    end

    test "downcases email" do
      attrs = %{
        email: "TEST@EXAMPLE.COM",
        password: "SecurePass123!"
      }

      changeset = User.new(attrs)
      assert changeset.changes.email == "test@example.com"
    end

    test "hashes password and removes plaintext" do
      attrs = %{
        email: "test@example.com",
        password: "SecurePass123!"
      }

      changeset = User.new(attrs)

      assert changeset.changes.password_hash
      assert String.starts_with?(changeset.changes.password_hash, "$argon2id$")
      refute Map.has_key?(changeset.changes, :password)
    end

    test "generates domain event for user creation" do
      attrs = %{
        email: "test@example.com",
        password: "SecurePass123!",
        username: "testuser"
      }

      changeset = User.new(attrs)

      assert_domain_event(changeset.changes.domain_events, "user_created")

      assert_domain_event_payload(changeset.changes.domain_events, "user_created", %{
        email: "test@example.com",
        username: "testuser"
      })
    end
  end

  describe "update_profile/2" do
    test "updates allowed profile fields" do
      user = Factory.build_user()

      attrs = %{
        first_name: "Jane",
        last_name: "Smith",
        phone: "+19876543210"
      }

      changeset = User.update_profile(user, attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.first_name == "Jane"
      assert changeset.changes.last_name == "Smith"
      assert changeset.changes.phone == "+19876543210"
    end

    test "validates phone number format" do
      user = Factory.build_user()
      changeset = User.update_profile(user, %{phone: "invalid-phone"})

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :phone, "must be a valid international phone number")
    end

    test "generates domain event for profile update" do
      user = Factory.build_user()
      changeset = User.update_profile(user, %{first_name: "Updated"})

      assert_domain_event(changeset.changes.domain_events, "user_updated")
    end

    test "does not allow updating email or password" do
      user = Factory.build_user()

      changeset =
        User.update_profile(user, %{
          email: "new@example.com",
          password: "NewPassword123!"
        })

      refute Map.has_key?(changeset.changes, :email)
      refute Map.has_key?(changeset.changes, :password)
    end
  end

  describe "change_password/2" do
    test "changes password with valid current password" do
      user = Factory.insert_user(%{password_hash: Argon2.hash_pwd_salt("CurrentPass123!")})

      attrs = %{
        current_password: "CurrentPass123!",
        password: "NewSecurePass123!",
        password_confirmation: "NewSecurePass123!"
      }

      changeset = User.change_password(user, attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.password_hash
      assert String.starts_with?(changeset.changes.password_hash, "$argon2id$")

      # Verify new password hash is different
      refute changeset.changes.password_hash == user.password_hash
    end

    test "fails with incorrect current password" do
      user = Factory.insert_user(%{password_hash: Argon2.hash_pwd_salt("CurrentPass123!")})

      attrs = %{
        current_password: "WrongPassword",
        password: "NewSecurePass123!"
      }

      changeset = User.change_password(user, attrs)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :current_password, "is incorrect")
    end

    test "validates password confirmation" do
      user = Factory.insert_user(%{password_hash: Argon2.hash_pwd_salt("CurrentPass123!")})

      attrs = %{
        current_password: "CurrentPass123!",
        password: "NewSecurePass123!",
        password_confirmation: "DifferentPassword"
      }

      changeset = User.change_password(user, attrs)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :password_confirmation, "does not match")
    end

    test "generates password changed domain event" do
      user = Factory.insert_user(%{password_hash: Argon2.hash_pwd_salt("CurrentPass123!")})

      attrs = %{
        current_password: "CurrentPass123!",
        password: "NewSecurePass123!",
        password_confirmation: "NewSecurePass123!"
      }

      changeset = User.change_password(user, attrs)

      assert_domain_event(changeset.changes.domain_events, "password_changed")
    end
  end

  describe "verify_email/1" do
    test "marks email as verified" do
      user = Factory.build_user(%{email_verified_at: nil})
      changeset = User.verify_email(user)

      assert_changeset_valid(changeset)
      assert changeset.changes.email_verified_at
      assert_recent_datetime(changeset.changes.email_verified_at)
    end

    test "generates email verified domain event" do
      user = Factory.build_user()
      changeset = User.verify_email(user)

      assert_domain_event(changeset.changes.domain_events, "email_verified")

      assert_domain_event_payload(changeset.changes.domain_events, "email_verified", %{
        email: user.email
      })
    end
  end

  describe "record_login/2" do
    test "updates login timestamp and resets failed attempts" do
      user =
        Factory.build_user(%{
          failed_login_attempts: 3,
          locked_until: DateTime.add(DateTime.utc_now(), 300, :second)
        })

      changeset = User.record_login(user, "192.168.1.1")

      assert_changeset_valid(changeset)
      assert changeset.changes.last_login_at
      assert changeset.changes.failed_login_attempts == 0
      assert changeset.changes.locked_until == nil
      assert_recent_datetime(changeset.changes.last_login_at)
    end

    test "generates login domain event with IP address" do
      user = Factory.build_user()
      changeset = User.record_login(user, "192.168.1.1")

      assert_domain_event(changeset.changes.domain_events, "user_logged_in")

      assert_domain_event_payload(changeset.changes.domain_events, "user_logged_in", %{
        ip_address: "192.168.1.1"
      })
    end
  end

  describe "record_failed_login/1" do
    test "increments failed login attempts" do
      user = Factory.build_user(%{failed_login_attempts: 2})
      changeset = User.record_failed_login(user)

      assert_changeset_valid(changeset)
      assert changeset.changes.failed_login_attempts == 3
      refute Map.has_key?(changeset.changes, :locked_until)
    end

    test "locks account after 5 failed attempts" do
      user = Factory.build_user(%{failed_login_attempts: 4})
      changeset = User.record_failed_login(user)

      assert_changeset_valid(changeset)
      assert changeset.changes.failed_login_attempts == 5
      assert changeset.changes.locked_until

      # Should be locked for about 15 minutes (900 seconds)
      lock_time = changeset.changes.locked_until
      now = DateTime.utc_now()
      assert DateTime.diff(lock_time, now, :second) > 800
      assert DateTime.diff(lock_time, now, :second) < 1000
    end

    test "generates failed login domain event" do
      user = Factory.build_user(%{failed_login_attempts: 2})
      changeset = User.record_failed_login(user)

      assert_domain_event(changeset.changes.domain_events, "login_failed")

      assert_domain_event_payload(changeset.changes.domain_events, "login_failed", %{
        attempts: 3
      })
    end
  end

  describe "delete/1" do
    test "soft deletes user" do
      user = Factory.build_user()
      changeset = User.delete(user)

      assert_changeset_valid(changeset)
      assert changeset.changes.deleted_at
      assert_recent_datetime(changeset.changes.deleted_at)
    end

    test "generates deletion domain event" do
      user = Factory.build_user()
      changeset = User.delete(user)

      assert_domain_event(changeset.changes.domain_events, "user_deleted")
    end
  end

  describe "restore/1" do
    test "restores soft deleted user" do
      user = Factory.build_deleted_user()
      changeset = User.restore(user)

      assert_changeset_valid(changeset)
      assert changeset.changes.deleted_at == nil
    end

    test "generates restoration domain event" do
      user = Factory.build_deleted_user()
      changeset = User.restore(user)

      assert_domain_event(changeset.changes.domain_events, "user_restored")
    end
  end

  describe "two-factor authentication" do
    test "enable_two_factor/2 enables 2FA" do
      user = Factory.build_user()
      secret = "JBSWY3DPEHPK3PXP"

      changeset = User.enable_two_factor(user, secret)

      assert_changeset_valid(changeset)
      assert changeset.changes.two_factor_enabled == true
      assert changeset.changes.two_factor_secret == secret
    end

    test "disable_two_factor/1 disables 2FA" do
      user = Factory.build_2fa_user()
      changeset = User.disable_two_factor(user)

      assert_changeset_valid(changeset)
      assert changeset.changes.two_factor_enabled == false
      assert changeset.changes.two_factor_secret == nil
    end

    test "generates appropriate domain events" do
      user = Factory.build_user()
      enable_changeset = User.enable_two_factor(user, "SECRET")

      assert_domain_event(enable_changeset.changes.domain_events, "two_factor_enabled")

      enabled_user = Factory.build_2fa_user()
      disable_changeset = User.disable_two_factor(enabled_user)

      assert_domain_event(disable_changeset.changes.domain_events, "two_factor_disabled")
    end
  end

  describe "locked?/1" do
    test "returns false for unlocked user" do
      user = Factory.build_user(%{locked_until: nil})
      refute User.locked?(user)
    end

    test "returns false for user with past lock time" do
      past_time = DateTime.add(DateTime.utc_now(), -300, :second)
      user = Factory.build_user(%{locked_until: past_time})
      refute User.locked?(user)
    end

    test "returns true for currently locked user" do
      future_time = DateTime.add(DateTime.utc_now(), 300, :second)
      user = Factory.build_user(%{locked_until: future_time})
      assert User.locked?(user)
    end
  end

  describe "can_login?/1" do
    test "returns true for active, unlocked user" do
      user = Factory.build_user()
      assert User.can_login?(user)
    end

    test "returns false for deleted user" do
      user = Factory.build_deleted_user()
      refute User.can_login?(user)
    end

    test "returns false for locked user" do
      user = Factory.build_locked_user()
      refute User.can_login?(user)
    end
  end

  describe "email_verified?/1" do
    test "returns false for unverified user" do
      user = Factory.build_unverified_user()
      refute User.email_verified?(user)
    end

    test "returns true for verified user" do
      user = Factory.build_user()
      assert User.email_verified?(user)
    end
  end

  describe "utility functions" do
    test "full_name/1 returns formatted full name" do
      user = Factory.build_user(%{first_name: "John", last_name: "Doe"})
      assert User.full_name(user) == "John Doe"
    end

    test "full_name/1 handles missing names" do
      user = Factory.build_user(%{first_name: "John", last_name: ""})
      assert User.full_name(user) == "John"

      user = Factory.build_user(%{first_name: "", last_name: "Doe"})
      assert User.full_name(user) == "Doe"

      user = Factory.build_user(%{first_name: nil, last_name: nil})
      assert User.full_name(user) == ""
    end

    test "display_name/1 prefers username over email" do
      user = Factory.build_user(%{username: "johndoe", email: "john@example.com"})
      assert User.display_name(user) == "johndoe"
    end

    test "display_name/1 falls back to email when no username" do
      user = Factory.build_user(%{username: nil, email: "john@example.com"})
      assert User.display_name(user) == "john@example.com"

      user = Factory.build_user(%{username: "", email: "john@example.com"})
      assert User.display_name(user) == "john@example.com"
    end
  end
end
