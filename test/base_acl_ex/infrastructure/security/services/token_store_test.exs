defmodule BaseAclEx.Infrastructure.Security.Services.TokenStoreTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Factory
  alias BaseAclEx.Infrastructure.Security.Entities.AccessToken
  alias BaseAclEx.Infrastructure.Security.Services.TokenStore

  describe "store_token/4" do
    test "successfully stores an access token" do
      user = Factory.insert_user()

      token = "sample.jwt.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "access",
        "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
      }

      opts = [
        ip_address: "192.168.1.1",
        user_agent: "Test/1.0",
        device_id: "device123",
        scopes: ["read", "write"]
      ]

      assert {:ok, stored_token} = TokenStore.store_token(user.id, token, claims, opts)

      assert stored_token.user_id == user.id
      assert stored_token.token_type == "access"
      assert stored_token.jti == claims["jti"]
      assert stored_token.ip_address == "192.168.1.1"
      assert stored_token.scopes == ["read", "write"]
      assert stored_token.used_count == 0
      refute stored_token.revoked_at
    end

    test "successfully stores a refresh token" do
      user = Factory.insert_user()
      access_token_id = Ecto.UUID.generate()

      token = "refresh.jwt.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "refresh",
        "exp" => DateTime.utc_now() |> DateTime.add(604_800, :second) |> DateTime.to_unix()
      }

      assert {:ok, stored_token} =
               TokenStore.store_refresh_token(user.id, token, claims, access_token_id)

      assert stored_token.user_id == user.id
      assert stored_token.token_type == "refresh"
      assert stored_token.refresh_token_id == access_token_id
    end

    test "enforces unique token_hash constraint" do
      user = Factory.insert_user()

      token = "duplicate.jwt.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "access",
        "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
      }

      # First insertion should succeed
      assert {:ok, _} = TokenStore.store_token(user.id, token, claims)

      # Second insertion with same token should fail
      claims2 = Map.put(claims, "jti", Ecto.UUID.generate())
      assert {:error, changeset} = TokenStore.store_token(user.id, token, claims2)
      assert changeset.errors[:token_hash]
    end
  end

  describe "token_revoked?/1" do
    test "returns false for non-revoked token" do
      user = Factory.insert_user()

      token = "active.jwt.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "access",
        "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
      }

      TokenStore.store_token(user.id, token, claims)

      refute TokenStore.token_revoked?(claims["jti"])
    end

    test "returns true for revoked token" do
      user = Factory.insert_user()

      token = "revoked.jwt.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "access",
        "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
      }

      TokenStore.store_token(user.id, token, claims)
      TokenStore.revoke_token(token)

      assert TokenStore.token_revoked?(claims["jti"])
    end
  end

  describe "validate_refresh_token/2" do
    test "validates active refresh token" do
      user = Factory.insert_user()

      token = "valid.refresh.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "refresh",
        "exp" => DateTime.utc_now() |> DateTime.add(604_800, :second) |> DateTime.to_unix()
      }

      {:ok, stored_token} = TokenStore.store_token(user.id, token, claims)

      assert {:ok, validated_token} = TokenStore.validate_refresh_token(token, user.id)
      assert validated_token.id == stored_token.id

      # Should increment usage count
      updated_token = Repo.reload(stored_token)
      assert updated_token.used_count == 1
      assert updated_token.last_used_at
    end

    test "rejects revoked refresh token" do
      user = Factory.insert_user()

      token = "revoked.refresh.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "refresh",
        "exp" => DateTime.utc_now() |> DateTime.add(604_800, :second) |> DateTime.to_unix()
      }

      TokenStore.store_token(user.id, token, claims)
      TokenStore.revoke_token(token)

      assert {:error, :token_revoked} = TokenStore.validate_refresh_token(token, user.id)
    end

    test "rejects expired refresh token" do
      user = Factory.insert_user()

      token = "expired.refresh.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "refresh",
        "exp" => DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_unix()
      }

      TokenStore.store_token(user.id, token, claims)

      assert {:error, :token_expired} = TokenStore.validate_refresh_token(token, user.id)
    end

    test "rejects token for wrong user" do
      user1 = Factory.insert_user()
      user2 = Factory.insert_user()

      token = "wrong.user.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "refresh",
        "exp" => DateTime.utc_now() |> DateTime.add(604_800, :second) |> DateTime.to_unix()
      }

      TokenStore.store_token(user1.id, token, claims)

      assert {:error, :token_not_found} = TokenStore.validate_refresh_token(token, user2.id)
    end
  end

  describe "revoke_all_user_tokens/3" do
    test "revokes all active tokens for a user" do
      user = Factory.insert_user()
      admin = Factory.insert_user()

      # Create multiple tokens
      for i <- 1..3 do
        token = "token#{i}.jwt"

        claims = %{
          "jti" => Ecto.UUID.generate(),
          "typ" => "access",
          "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
        }

        TokenStore.store_token(user.id, token, claims)
      end

      # Verify tokens are active
      active_tokens = TokenStore.get_user_active_tokens(user.id)
      assert length(active_tokens) == 3

      # Revoke all tokens
      {count, _} = TokenStore.revoke_all_user_tokens(user.id, admin.id, "security_incident")
      assert count == 3

      # Verify tokens are revoked
      active_tokens = TokenStore.get_user_active_tokens(user.id)
      assert Enum.empty?(active_tokens)
    end

    test "doesn't affect other users' tokens" do
      user1 = Factory.insert_user()
      user2 = Factory.insert_user()

      # Create tokens for both users
      for user <- [user1, user2] do
        token = "token.#{user.id}.jwt"

        claims = %{
          "jti" => Ecto.UUID.generate(),
          "typ" => "access",
          "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
        }

        TokenStore.store_token(user.id, token, claims)
      end

      # Revoke tokens for user1 only
      {count, _} = TokenStore.revoke_all_user_tokens(user1.id)
      assert count == 1

      # Verify user2's tokens are still active
      user2_active = TokenStore.get_user_active_tokens(user2.id)
      assert length(user2_active) == 1
    end
  end

  describe "cleanup_expired_tokens/0" do
    test "removes expired tokens" do
      user = Factory.insert_user()

      # Create expired token
      expired_token = "expired.jwt.token"

      expired_claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "access",
        "exp" => DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_unix()
      }

      # Create active token
      active_token = "active.jwt.token"

      active_claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "access",
        "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
      }

      TokenStore.store_token(user.id, expired_token, expired_claims)
      TokenStore.store_token(user.id, active_token, active_claims)

      # Verify we have 2 tokens
      assert Repo.aggregate(AccessToken, :count) == 2

      # Run cleanup
      {cleaned_count, _} = TokenStore.cleanup_expired_tokens()
      assert cleaned_count == 1

      # Verify only active token remains
      assert Repo.aggregate(AccessToken, :count) == 1
      remaining_token = Repo.one(AccessToken)
      assert remaining_token.jti == active_claims["jti"]
    end
  end

  describe "get_user_devices/1" do
    test "returns unique devices with aggregated stats" do
      user = Factory.insert_user()

      # Create tokens for same device
      device_id = "device123"

      for i <- 1..3 do
        token = "token#{i}.jwt"

        claims = %{
          "jti" => Ecto.UUID.generate(),
          "typ" => "access",
          "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
        }

        opts = [
          device_id: device_id,
          device_name: "Test Device",
          user_agent: "TestAgent/1.0"
        ]

        TokenStore.store_token(user.id, token, claims, opts)
      end

      devices = TokenStore.get_user_devices(user.id)

      assert length(devices) == 1
      device = List.first(devices)
      assert device.device_id == device_id
      assert device.device_name == "Test Device"
      assert device.token_count == 3
    end
  end

  describe "detect_threats/1" do
    test "detects multiple location access" do
      user = Factory.insert_user()

      # Create tokens from different IPs
      ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "203.0.113.1"]

      for ip <- ips do
        token = "token.#{ip}.jwt"

        claims = %{
          "jti" => Ecto.UUID.generate(),
          "typ" => "access",
          "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
        }

        {:ok, stored_token} = TokenStore.store_token(user.id, token, claims, ip_address: ip)

        # Update last_used_at to current time to simulate recent usage
        stored_token
        |> AccessToken.update_usage(ip)
        |> Repo.update!()
      end

      threats = TokenStore.detect_threats(user.id)

      # Should detect multiple locations threat
      multiple_location_threat = Enum.find(threats, &(&1.type == :multiple_locations))
      assert multiple_location_threat
      assert multiple_location_threat.severity == :medium
      assert length(multiple_location_threat.details.ip_addresses) == 4
    end

    test "doesn't detect threats for normal usage" do
      user = Factory.insert_user()

      # Create normal token usage pattern
      token = "normal.token.jwt"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "access",
        "exp" => DateTime.utc_now() |> DateTime.add(900, :second) |> DateTime.to_unix()
      }

      TokenStore.store_token(user.id, token, claims, ip_address: "192.168.1.1")

      threats = TokenStore.detect_threats(user.id)
      assert Enum.empty?(threats)
    end
  end

  describe "token lifecycle management" do
    test "complete token lifecycle with rotation" do
      user = Factory.insert_user()

      # 1. Create initial refresh token
      token = "initial.refresh.token"

      claims = %{
        "jti" => Ecto.UUID.generate(),
        "typ" => "refresh",
        "exp" => DateTime.utc_now() |> DateTime.add(604_800, :second) |> DateTime.to_unix()
      }

      {:ok, token_record} = TokenStore.store_token(user.id, token, claims)

      # 2. Simulate heavy usage to trigger rotation condition
      for _i <- 1..15 do
        token_record
        |> AccessToken.update_usage()
        |> Repo.update!()

        token_record = Repo.reload(token_record)
      end

      # 3. Check if token should be rotated
      updated_token = Repo.reload(token_record)
      assert AccessToken.should_rotate?(updated_token)

      # 4. Revoke the token
      {:ok, revoked_token} = TokenStore.revoke_token(token, user.id, "rotated")
      assert revoked_token.revoked_at
      assert revoked_token.revoke_reason == "rotated"
      assert revoked_token.revoked_by_id == user.id

      # 5. Verify token is now considered revoked
      assert TokenStore.token_revoked?(claims["jti"])
    end
  end
end
