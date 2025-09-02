defmodule BaseAclEx.Accounts.Core.ValueObjects.PasswordTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Accounts.Core.ValueObjects.Password
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  describe "new/1" do
    test "creates valid password value object" do
      plain_password = "SecurePass123!"

      assert {:ok, password} = Password.new(plain_password)
      assert password.algorithm == "argon2"
      assert password.hash
      assert String.starts_with?(password.hash, "$argon2id$")
      assert_recent_datetime(password.last_changed_at)
    end

    test "validates password strength - minimum length" do
      assert {:error, :password_too_short} = Password.new("Abc1!")
      assert {:ok, _} = Password.new("Abc12345!")
    end

    test "validates password strength - maximum length" do
      long_password = String.duplicate("A", 120) <> "1a!"
      assert {:ok, _} = Password.new(long_password)

      too_long_password = String.duplicate("A", 125) <> "1a!"
      assert {:error, :password_too_long} = Password.new(too_long_password)
    end

    test "validates complexity requirements" do
      test_cases = [
        {"nouppercase123!", {:weak_password, [:missing_uppercase]}},
        {"NOLOWERCASE123!", {:weak_password, [:missing_lowercase]}},
        {"NoNumbers!", {:weak_password, [:missing_number]}},
        {"NoSpecialChar123", {:weak_password, [:missing_special_char]}}
      ]

      for {password, expected_error} <- test_cases do
        assert {:error, expected_error} = Password.new(password)
      end
    end

    test "rejects common passwords" do
      common_passwords = [
        "password123!A",
        "MyPassword123!",
        "Qwerty123!",
        "Admin123!",
        "Welcome123!"
      ]

      for password <- common_passwords do
        assert {:error, :common_password} = Password.new(password)
      end
    end

    test "accepts secure passwords" do
      secure_passwords = [
        "MySecureP@ssw0rd",
        "Tr0ub4dor&3",
        "C0mpl3xP@$$w0rd",
        "Un1qu3&Str0ng!"
      ]

      for password <- secure_passwords do
        assert {:ok, _} = Password.new(password)
      end
    end

    test "rejects non-string inputs" do
      assert {:error, :invalid_password} = Password.new(123)
      assert {:error, :invalid_password} = Password.new(nil)
      assert {:error, :invalid_password} = Password.new(:atom)
    end
  end

  describe "from_hash/2" do
    test "creates password from existing hash" do
      hash = "$argon2id$v=19$m=65536,t=1,p=1$SomeHashedPassword"

      password = Password.from_hash(hash)

      assert password.hash == hash
      assert password.algorithm == "argon2"
      refute password.must_change
    end

    test "accepts custom options" do
      hash = "$argon2id$v=19$m=65536,t=1,p=1$SomeHashedPassword"
      last_changed = DateTime.add(DateTime.utc_now(), -30, :day)
      expires_at = DateTime.add(DateTime.utc_now(), 60, :day)

      password =
        Password.from_hash(hash,
          algorithm: "bcrypt",
          last_changed_at: last_changed,
          expires_at: expires_at,
          must_change: true
        )

      assert password.hash == hash
      assert password.algorithm == "bcrypt"
      assert password.last_changed_at == last_changed
      assert password.expires_at == expires_at
      assert password.must_change == true
    end
  end

  describe "validate_strength/1" do
    test "returns ok for valid passwords" do
      assert :ok = Password.validate_strength("SecureP@ss123")
    end

    test "returns error for invalid passwords" do
      assert {:error, :password_too_short} = Password.validate_strength("Short1!")

      assert {:error, {:weak_password, [:missing_uppercase]}} =
               Password.validate_strength("lowercase123!")

      assert {:error, :common_password} = Password.validate_strength("Password123!")
    end

    test "rejects non-string inputs" do
      assert {:error, :invalid_password} = Password.validate_strength(nil)
      assert {:error, :invalid_password} = Password.validate_strength(123)
    end
  end

  describe "hash_password/1" do
    test "generates argon2 hash" do
      hash = Password.hash_password("TestPassword123!")

      assert String.starts_with?(hash, "$argon2id$")
      assert String.length(hash) > 50
    end

    test "generates different hashes for same password" do
      password = "TestPassword123!"
      hash1 = Password.hash_password(password)
      hash2 = Password.hash_password(password)

      refute hash1 == hash2
    end
  end

  describe "verify/2" do
    test "verifies correct password" do
      plain_password = "TestPassword123!"
      {:ok, password} = Password.new(plain_password)

      assert Password.verify(password, plain_password)
    end

    test "rejects incorrect password" do
      plain_password = "TestPassword123!"
      {:ok, password} = Password.new(plain_password)

      refute Password.verify(password, "WrongPassword123!")
    end

    test "rejects invalid inputs" do
      {:ok, password} = Password.new("TestPassword123!")

      refute Password.verify(password, nil)
      refute Password.verify(password, 123)
      refute Password.verify("invalid", "password")
    end
  end

  describe "expired?/1" do
    test "returns false for non-expiring passwords" do
      password = %Password{expires_at: nil}
      refute Password.expired?(password)
    end

    test "returns false for future expiration" do
      future_date = DateTime.add(DateTime.utc_now(), 30, :day)
      password = %Password{expires_at: future_date}
      refute Password.expired?(password)
    end

    test "returns true for past expiration" do
      past_date = DateTime.add(DateTime.utc_now(), -1, :day)
      password = %Password{expires_at: past_date}
      assert Password.expired?(password)
    end
  end

  describe "must_change?/1" do
    test "returns value of must_change flag" do
      password_no_change = %Password{must_change: false}
      password_must_change = %Password{must_change: true}

      refute Password.must_change?(password_no_change)
      assert Password.must_change?(password_must_change)
    end
  end

  describe "set_expiration/2" do
    test "sets expiration date based on days" do
      password = %Password{}
      updated_password = Password.set_expiration(password, 90)

      assert updated_password.expires_at

      # Should be approximately 90 days from now
      now = DateTime.utc_now()
      expected_date = DateTime.add(now, 90 * 24 * 60 * 60, :second)
      assert_datetime_within(updated_password.expires_at, expected_date, 60)
    end

    test "handles different day values" do
      password = %Password{}

      # 30 days
      updated_30 = Password.set_expiration(password, 30)
      # 365 days
      updated_365 = Password.set_expiration(password, 365)

      assert DateTime.compare(updated_365.expires_at, updated_30.expires_at) == :gt
    end
  end

  describe "require_change/1" do
    test "marks password as requiring change" do
      password = %Password{must_change: false}
      updated_password = Password.require_change(password)

      assert updated_password.must_change == true
    end
  end

  describe "integration scenarios" do
    test "password lifecycle - creation to verification" do
      # Create new password
      plain_password = "MySecureP@ssw0rd123"
      {:ok, password} = Password.new(plain_password)

      # Verify it works
      assert Password.verify(password, plain_password)
      refute Password.verify(password, "WrongPassword123!")

      # Check it's not expired and doesn't require change
      refute Password.expired?(password)
      refute Password.must_change?(password)

      # Set expiration and require change
      updated_password =
        password
        |> Password.set_expiration(90)
        |> Password.require_change()

      assert updated_password.expires_at
      assert Password.must_change?(updated_password)
      refute Password.expired?(updated_password)
    end

    test "password security policies enforcement" do
      # Test various insecure passwords
      insecure_cases = [
        {"password", :common_password},
        {"12345678", :common_password},
        {"Short1!", :password_too_short},
        {"toolong" <> String.duplicate("a", 125) <> "A1!", :password_too_long},
        {"nouppercase123!", {:weak_password, [:missing_uppercase]}},
        {"NOLOWERCASE123!", {:weak_password, [:missing_lowercase]}},
        {"NoNumbers!", {:weak_password, [:missing_number]}},
        {"NoSpecialChar123", {:weak_password, [:missing_special_char]}}
      ]

      for {password, expected_error} <- insecure_cases do
        assert {:error, expected_error} = Password.new(password),
               "Password '#{password}' should fail with #{inspect(expected_error)}"
      end

      # Test secure password succeeds
      assert {:ok, _} = Password.new("MySecure&Complex123!")
    end

    test "password comparison and hashing consistency" do
      passwords = [
        "FirstSecureP@ss123",
        "SecondSecureP@ss456",
        "ThirdSecureP@ss789"
      ]

      password_objects =
        Enum.map(passwords, fn p ->
          {:ok, password_obj} = Password.new(p)
          {p, password_obj}
        end)

      # Each password should verify against its own hash
      for {plain, password_obj} <- password_objects do
        assert Password.verify(password_obj, plain)
      end

      # Each password should not verify against others
      for {plain1, password_obj1} <- password_objects do
        for {plain2, _} <- password_objects do
          if plain1 != plain2 do
            refute Password.verify(password_obj1, plain2)
          end
        end
      end

      # All hashes should be different
      hashes = Enum.map(password_objects, fn {_, obj} -> obj.hash end)
      assert length(Enum.uniq(hashes)) == length(hashes)
    end
  end
end
