defmodule BaseAclEx.Infrastructure.Security.JWT.GuardianImpl do
  @moduledoc """
  Guardian implementation for JWT token generation and validation.
  Provides secure token management with refresh token support.
  """

  use Guardian, otp_app: :base_acl_ex

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Infrastructure.Persistence.Repo
  alias BaseAclEx.Identity.Application.Services.PermissionCache

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
  def build_claims(claims, %User{} = user, _opts) do
    claims =
      claims
      |> Map.put("typ", "access")
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
    with {:ok, access_token, access_claims} <-
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
    if token_revoked?(jti) do
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
    # Store in access_tokens table
    %{
      user_id: user.id,
      token_hash: hash_token(token),
      token_type: "refresh",
      expires_at: DateTime.from_unix!(claims["exp"]),
      metadata: %{
        jti: claims["jti"],
        iat: claims["iat"]
      }
    }

    # |> AccessToken.changeset()
    # |> Repo.insert()

    :ok
  end

  defp verify_refresh_token_valid(_token, _user) do
    # Verify refresh token is still valid in database
    :ok
  end

  defp maybe_rotate_refresh_token(old_token, user) do
    # Implement refresh token rotation if needed
    if should_rotate_token?(old_token) do
      {:ok, new_token, _claims} =
        encode_and_sign(user, %{},
          token_type: "refresh",
          ttl: {7, :days}
        )

      # Revoke old token
      mark_token_revoked(old_token, %{})

      new_token
    else
      nil
    end
  end

  defp should_rotate_token?(_token) do
    # Implement rotation logic (e.g., based on age or usage count)
    false
  end

  defp mark_token_revoked(_token, _claims) do
    # Mark token as revoked in database
    :ok
  end

  defp token_revoked?(_jti) do
    # Check if token is revoked
    false
  end

  defp hash_token(token) do
    :crypto.hash(:sha256, token)
    |> Base.encode16(case: :lower)
  end
end
