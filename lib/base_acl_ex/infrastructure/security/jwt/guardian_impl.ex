defmodule BaseAclEx.Infrastructure.Security.JWT.GuardianImpl do
  @moduledoc """
  Guardian implementation for JWT token generation and validation.
  Provides secure token management with refresh token support.
  """

  use Guardian, otp_app: :base_acl_ex

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Application.Services.PermissionCache
  alias BaseAclEx.Infrastructure.Security.Entities.AccessToken
  alias BaseAclEx.Infrastructure.Security.Services.TokenStore
  alias BaseAclEx.Repo

  @impl Guardian
  def subject_for_token(%User{id: user_id}, _claims) do
    {:ok, to_string(user_id)}
  end

  def subject_for_token(_, _) do
    {:error, :invalid_resource}
  end

  @impl Guardian
  def resource_from_claims(%{"sub" => user_id} = claims) do
    case Repo.get(User, user_id) do
      nil ->
        {:error, :resource_not_found}

      user ->
        # Preload permissions if needed
        user = maybe_preload_permissions(user, claims)
        {:ok, user}
    end
  end

  def resource_from_claims(_claims) do
    {:error, :invalid_claims}
  end

  @impl Guardian
  def build_claims(claims, %User{} = user, opts) do
    # Ensure JTI is always present for token revocation support
    jti = Map.get(claims, "jti") || Ecto.UUID.generate()
    token_type = Keyword.get(opts, :token_type, "access")

    claims =
      claims
      |> Map.put("jti", jti)
      |> Map.put("typ", token_type)
      |> Map.put("aud", "base_acl_ex")
      |> Map.put("email", user.email)
      |> Map.put("roles", get_user_roles(user))
      |> Map.put("permissions", get_user_permissions(user))

    {:ok, claims}
  end

  def build_claims(claims, _resource, _opts) do
    {:ok, claims}
  end

  @impl Guardian
  def verify_claims(claims, _opts) do
    with :ok <- verify_token_type(claims),
         :ok <- verify_audience(claims),
         :ok <- verify_not_revoked(claims) do
      {:ok, claims}
    end
  end

  @doc """
  Generates both access and refresh tokens for a user.
  """
  def generate_tokens(%User{} = user) do
    with {:ok, access_token, _access_claims} <-
           encode_and_sign(user, %{},
             token_type: "access",
             ttl: {15, :minutes}
           ),
         {:ok, refresh_token, refresh_claims} <-
           encode_and_sign(user, %{},
             token_type: "refresh",
             ttl: {7, :days}
           ) do
      # Store refresh token in database for revocation support
      store_refresh_token(user, refresh_token, refresh_claims)

      {:ok,
       %{
         access_token: access_token,
         refresh_token: refresh_token,
         expires_in: 900,
         token_type: "Bearer"
       }}
    end
  end

  @doc """
  Refreshes an access token using a refresh token.
  """
  def refresh_access_token(refresh_token) do
    with {:ok, claims} <- decode_and_verify(refresh_token, %{"typ" => "refresh"}),
         {:ok, user} <- resource_from_claims(claims),
         :ok <- verify_refresh_token_valid(refresh_token, user) do
      # Generate new access token
      {:ok, access_token, _claims} =
        encode_and_sign(user, %{},
          token_type: "access",
          ttl: {15, :minutes}
        )

      # Optionally rotate refresh token
      rotated_refresh = maybe_rotate_refresh_token(refresh_token, user)

      {:ok,
       %{
         access_token: access_token,
         refresh_token: rotated_refresh || refresh_token,
         expires_in: 900,
         token_type: "Bearer"
       }}
    end
  end

  @doc """
  Revokes a token (typically refresh token).
  """
  def revoke_token(token) do
    with {:ok, claims} <- decode_and_verify(token),
         {:ok, _user} <- resource_from_claims(claims) do
      # Mark token as revoked in database
      mark_token_revoked(token, claims)
      {:ok, claims}
    end
  end

  @doc """
  Validates token permissions against required permissions.
  """
  def validate_permissions(token, required_permissions) do
    with {:ok, claims} <- decode_and_verify(token),
         {:ok, user} <- resource_from_claims(claims) do
      user_permissions = get_user_permissions(user)

      has_all_permissions =
        Enum.all?(required_permissions, fn perm ->
          perm in user_permissions
        end)

      if has_all_permissions do
        {:ok, user}
      else
        {:error, :insufficient_permissions}
      end
    end
  end

  # Private functions

  defp verify_token_type(%{"typ" => type}) when type in ["access", "refresh"], do: :ok
  defp verify_token_type(_), do: {:error, :invalid_token_type}

  defp verify_audience(%{"aud" => "base_acl_ex"}), do: :ok
  defp verify_audience(_), do: {:error, :invalid_audience}

  defp verify_not_revoked(%{"jti" => jti}) do
    # Check if token is revoked in database
    if TokenStore.token_revoked?(jti) do
      {:error, :token_revoked}
    else
      :ok
    end
  end

  defp verify_not_revoked(_), do: :ok

  defp get_user_roles(%User{} = user) do
    # Fetch from cache or database
    case PermissionCache.get_user_permissions(user.id) do
      {:ok, permissions} ->
        permissions
        |> Enum.map(&Map.get(&1, :role_slug))
        |> Enum.uniq()
        |> Enum.reject(&is_nil/1)

      _ ->
        # Fallback to database query
        []
    end
  end

  defp get_user_permissions(%User{} = user) do
    case PermissionCache.get_user_permissions(user.id) do
      {:ok, permissions} ->
        permissions
        |> Enum.map(&Map.get(&1, :name))
        |> Enum.uniq()

      _ ->
        []
    end
  end

  defp maybe_preload_permissions(user, %{"include_permissions" => true}) do
    # Preload permissions if requested
    user
    # |> Repo.preload([:roles, :permissions])
  end

  defp maybe_preload_permissions(user, _), do: user

  defp store_refresh_token(user, token, claims) do
    # Store refresh token in database
    case TokenStore.store_token(user.id, token, claims) do
      {:ok, _token_record} ->
        :ok

      {:error, changeset} ->
        require Logger
        Logger.error("Failed to store refresh token: #{inspect(changeset.errors)}")
        # Don't fail token generation if storage fails
        :ok
    end
  end

  defp verify_refresh_token_valid(token, user) do
    case TokenStore.validate_refresh_token(token, user.id) do
      {:ok, _token_record} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp maybe_rotate_refresh_token(old_token, user) do
    # Check if token should be rotated
    token_hash = hash_token(old_token)

    case TokenStore.get_token_by_hash(token_hash) do
      %AccessToken{} = token_record ->
        if AccessToken.should_rotate?(token_record) do
          # Generate new refresh token
          {:ok, new_token, new_claims} =
            encode_and_sign(user, %{},
              token_type: "refresh",
              ttl: {7, :days}
            )

          # Store new token
          TokenStore.store_token(user.id, new_token, new_claims)

          # Revoke old token
          TokenStore.revoke_token(old_token, nil, "rotated")

          new_token
        else
          nil
        end

      nil ->
        # Token not found in database, don't rotate
        nil
    end
  end

  # This function is no longer needed as logic moved to AccessToken.should_rotate?/1

  defp mark_token_revoked(token, claims) do
    reason = Map.get(claims, "revoke_reason", "manual_revocation")
    revoked_by_id = Map.get(claims, "revoked_by_id")

    case TokenStore.revoke_token(token, revoked_by_id, reason) do
      {:ok, _token_record} -> :ok
      # Already revoked or doesn't exist
      {:error, :token_not_found} -> :ok
    end
  end

  # This function is replaced by TokenStore.token_revoked?/1

  defp hash_token(token) do
    :crypto.hash(:sha256, token)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Revokes all tokens for a user (logout from all devices).
  """
  def revoke_all_user_tokens(user_id, revoked_by_id \\ nil, reason \\ "logout_all") do
    {count, _} = TokenStore.revoke_all_user_tokens(user_id, revoked_by_id, reason)
    {:ok, %{revoked_count: count}}
  end

  @doc """
  Revokes tokens for a specific device.
  """
  def revoke_device_tokens(user_id, device_id, revoked_by_id \\ nil) do
    {count, _} = TokenStore.revoke_device_tokens(user_id, device_id, revoked_by_id)
    {:ok, %{revoked_count: count}}
  end

  @doc """
  Gets user's active devices.
  """
  def get_user_devices(user_id) do
    devices = TokenStore.get_user_devices(user_id)
    {:ok, devices}
  end

  @doc """
  Gets user token statistics.
  """
  def get_user_token_stats(user_id) do
    stats = TokenStore.get_user_token_stats(user_id)
    {:ok, stats}
  end

  @doc """
  Enhanced token generation with device tracking and metadata.
  """
  def generate_tokens_with_metadata(%User{} = user, opts \\ []) do
    ip_address = Keyword.get(opts, :ip_address)
    user_agent = Keyword.get(opts, :user_agent)
    device_id = Keyword.get(opts, :device_id)
    device_name = Keyword.get(opts, :device_name)
    remember_me = Keyword.get(opts, :remember_me, false)
    scopes = Keyword.get(opts, :scopes, [])

    # Set TTL based on remember_me option
    access_ttl = {15, :minutes}
    refresh_ttl = if remember_me, do: {30, :days}, else: {7, :days}

    with {:ok, access_token, access_claims} <-
           encode_and_sign(user, %{},
             token_type: "access",
             ttl: access_ttl
           ),
         {:ok, refresh_token, refresh_claims} <-
           encode_and_sign(user, %{},
             token_type: "refresh",
             ttl: refresh_ttl
           ) do
      # Store both tokens in database
      token_opts = [
        ip_address: ip_address,
        user_agent: user_agent,
        device_id: device_id,
        device_name: device_name,
        scopes: scopes,
        metadata: %{
          remember_me: remember_me,
          generated_at: DateTime.utc_now()
        }
      ]

      # Store access token
      {:ok, access_record} =
        TokenStore.store_token(user.id, access_token, access_claims, token_opts)

      # Store refresh token with reference to access token
      refresh_opts = Keyword.put(token_opts, :refresh_token_id, access_record.id)
      TokenStore.store_token(user.id, refresh_token, refresh_claims, refresh_opts)

      {:ok,
       %{
         access_token: access_token,
         refresh_token: refresh_token,
         # 30 min for remember_me, 15 min normal
         expires_in: if(remember_me, do: 1800, else: 900),
         token_type: "Bearer",
         scope: Enum.join(scopes, " "),
         # 30 days vs 7 days
         refresh_expires_in: if(remember_me, do: 2_592_000, else: 604_800)
       }}
    end
  end
end
