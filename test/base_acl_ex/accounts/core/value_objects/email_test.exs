defmodule BaseAclEx.Accounts.Core.ValueObjects.EmailTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Accounts.Core.ValueObjects.Email
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  describe "new/1" do
    test "creates valid email value object" do
      email_string = "user@example.com"

      assert {:ok, email} = Email.new(email_string)
      assert email.value == email_string
      assert email.normalized == "user@example.com"
      assert email.domain == "example.com"
      refute email.verified
      assert email.verified_at == nil
    end

    test "normalizes email during creation" do
      assert {:ok, email} = Email.new("  USER@EXAMPLE.COM  ")
      assert email.value == "  USER@EXAMPLE.COM  "
      assert email.normalized == "user@example.com"
      assert email.domain == "example.com"
    end

    test "accepts various valid email formats" do
      valid_emails = [
        "user@example.com",
        "user.name@example.com",
        "user+tag@example.com",
        "user123@example.co.uk",
        "test.email-with-dash@example.com",
        "user@sub.example.com",
        "a@b.co",
        "very.long.email.address@very.long.domain.example.com"
      ]

      for email_string <- valid_emails do
        assert {:ok, _} = Email.new(email_string),
               "Email '#{email_string}' should be valid"
      end
    end

    test "rejects invalid email formats" do
      invalid_emails = [
        "invalid-email",
        "@example.com",
        "user@",
        "user@@example.com",
        "user..name@example.com",
        "user@.example.com",
        "user@example.",
        "user name@example.com",
        "",
        "user@",
        "user@example",
        "user@example..com"
      ]

      for email_string <- invalid_emails do
        assert {:error, :invalid_email} = Email.new(email_string),
               "Email '#{email_string}' should be invalid"
      end
    end

    test "rejects email longer than 254 characters" do
      # Create an email that's exactly 255 characters (too long)
      long_local = String.duplicate("a", 64)
      long_domain = String.duplicate("b", 189) <> ".com"
      long_email = "#{long_local}@#{long_domain}"

      assert String.length(long_email) > 254
      assert {:error, :invalid_email} = Email.new(long_email)
    end

    test "accepts email with exactly 254 characters" do
      # Create an email that's exactly 254 characters (valid length)
      local = String.duplicate("a", 64)
      domain = String.duplicate("b", 187) <> ".com"
      valid_email = "#{local}@#{domain}"

      assert String.length(valid_email) == 254
      assert {:ok, _} = Email.new(valid_email)
    end

    test "rejects non-string inputs" do
      assert {:error, :invalid_email} = Email.new(123)
      assert {:error, :invalid_email} = Email.new(nil)
      assert {:error, :invalid_email} = Email.new(:atom)
      assert {:error, :invalid_email} = Email.new(["list"])
    end
  end

  describe "new!/1" do
    test "creates email value object for valid input" do
      email = Email.new!("user@example.com")
      assert email.value == "user@example.com"
    end

    test "raises for invalid email" do
      assert_raise ArgumentError, "Invalid email: invalid_email", fn ->
        Email.new!("invalid-email")
      end
    end
  end

  describe "valid?/1" do
    test "validates correct email addresses" do
      valid_cases = [
        "user@example.com",
        "test.email@example.co.uk",
        "user+tag@example.com",
        "a@b.co"
      ]

      for email <- valid_cases do
        assert Email.valid?(email), "#{email} should be valid"
      end
    end

    test "rejects incorrect email addresses" do
      invalid_cases = [
        "invalid-email",
        "@example.com",
        "user@",
        "user@@example.com",
        nil,
        123,
        ""
      ]

      for email <- invalid_cases do
        refute Email.valid?(email), "#{inspect(email)} should be invalid"
      end
    end

    test "handles edge cases" do
      refute Email.valid?(nil)
      refute Email.valid?("")
      refute Email.valid?("   ")
      refute Email.valid?(123)
    end
  end

  describe "normalize/1" do
    test "normalizes email addresses" do
      test_cases = [
        {"USER@EXAMPLE.COM", "user@example.com"},
        {"  user@example.com  ", "user@example.com"},
        {"User.Name@Example.Com", "user.name@example.com"},
        {"", ""}
      ]

      for {input, expected} <- test_cases do
        assert Email.normalize(input) == expected
      end
    end

    test "handles non-string inputs" do
      assert Email.normalize(nil) == ""
      assert Email.normalize(123) == ""
      assert Email.normalize(:atom) == ""
    end
  end

  describe "extract_domain/1" do
    test "extracts domain from email addresses" do
      test_cases = [
        {"user@example.com", "example.com"},
        {"test@sub.example.co.uk", "sub.example.co.uk"},
        {"admin@localhost", "localhost"},
        {"user+tag@example.org", "example.org"}
      ]

      for {email, expected_domain} <- test_cases do
        assert Email.extract_domain(email) == expected_domain
      end
    end

    test "handles invalid email formats" do
      invalid_cases = [
        "invalid-email",
        "@example.com",
        "user@",
        "",
        nil,
        123
      ]

      for email <- invalid_cases do
        assert Email.extract_domain(email) == nil
      end
    end
  end

  describe "mark_as_verified/1" do
    test "marks email as verified with timestamp" do
      {:ok, email} = Email.new("user@example.com")
      verified_email = Email.mark_as_verified(email)

      assert verified_email.verified == true
      assert verified_email.verified_at
      assert_recent_datetime(verified_email.verified_at)
    end

    test "preserves other email attributes" do
      {:ok, email} = Email.new("User@Example.Com")
      verified_email = Email.mark_as_verified(email)

      assert verified_email.value == email.value
      assert verified_email.normalized == email.normalized
      assert verified_email.domain == email.domain
    end
  end

  describe "from_domain?/2" do
    test "checks if email belongs to specific domain" do
      {:ok, email} = Email.new("user@example.com")

      assert Email.from_domain?(email, "example.com")
      # case insensitive
      assert Email.from_domain?(email, "EXAMPLE.COM")
      refute Email.from_domain?(email, "other.com")
      refute Email.from_domain?(email, "sub.example.com")
    end

    test "handles edge cases" do
      {:ok, email} = Email.new("user@sub.example.com")

      assert Email.from_domain?(email, "sub.example.com")
      refute Email.from_domain?(email, "example.com")
    end
  end

  describe "to_string/1" do
    test "returns original email value" do
      original = "User@Example.Com"
      {:ok, email} = Email.new(original)

      assert Email.to_string(email) == original
    end
  end

  describe "String.Chars protocol" do
    test "implements to_string protocol" do
      {:ok, email} = Email.new("user@example.com")
      assert to_string(email) == "user@example.com"
    end

    test "can be used in string interpolation" do
      {:ok, email} = Email.new("user@example.com")
      message = "Welcome #{email}!"
      assert message == "Welcome user@example.com!"
    end
  end

  describe "integration scenarios" do
    test "email verification workflow" do
      # Create new email
      {:ok, email} = Email.new("  User@Example.Com  ")

      # Initially not verified
      refute email.verified
      assert email.verified_at == nil

      # Check domain and formatting
      assert email.value == "  User@Example.Com  "
      assert email.normalized == "user@example.com"
      assert email.domain == "example.com"
      assert Email.from_domain?(email, "example.com")

      # Mark as verified
      verified_email = Email.mark_as_verified(email)

      assert verified_email.verified
      assert verified_email.verified_at
      assert_recent_datetime(verified_email.verified_at)

      # Original properties preserved
      assert verified_email.value == email.value
      assert verified_email.normalized == email.normalized
      assert verified_email.domain == email.domain
    end

    test "email comparison and domain filtering" do
      emails = [
        "user1@example.com",
        "user2@example.com",
        "user3@other.com",
        "admin@example.org"
      ]

      email_objects =
        Enum.map(emails, fn e ->
          {:ok, obj} = Email.new(e)
          {e, obj}
        end)

      # Filter by domain
      example_com_emails =
        email_objects
        |> Enum.filter(fn {_, obj} -> Email.from_domain?(obj, "example.com") end)
        |> Enum.map(fn {str, _} -> str end)

      assert length(example_com_emails) == 2
      assert "user1@example.com" in example_com_emails
      assert "user2@example.com" in example_com_emails
      refute "user3@other.com" in example_com_emails

      # Test case insensitivity
      example_org_count =
        email_objects
        |> Enum.count(fn {_, obj} -> Email.from_domain?(obj, "EXAMPLE.ORG") end)

      assert example_org_count == 1
    end

    test "email normalization consistency" do
      variations = [
        "User@Example.Com",
        "USER@EXAMPLE.COM",
        "  user@example.com  ",
        "user@EXAMPLE.com"
      ]

      normalized_emails =
        Enum.map(variations, fn email ->
          {:ok, obj} = Email.new(email)
          obj.normalized
        end)

      # All should normalize to the same value
      assert Enum.uniq(normalized_emails) == ["user@example.com"]

      # But preserve original values
      original_values =
        Enum.map(variations, fn email ->
          {:ok, obj} = Email.new(email)
          obj.value
        end)

      assert original_values == variations
    end
  end
end
