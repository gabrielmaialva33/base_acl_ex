defmodule BaseAclEx.Infrastructure.Security.Services.TokenStore do
  @moduledoc """
  Service for managing JWT token storage, revocation, and lifecycle.
  Provides secure token persistence with revocation blacklist support.
  """

  import Ecto.Query
  require Logger

  alias BaseAclEx.Repo
  alias BaseAclEx.Infrastructure.Security.Entities.AccessToken
  alias BaseAclEx.Accounts.Core.Entities.User

  @hash_algorithm :sha256

  @doc """
  Stores a token in the database.
  """
  @spec store_token(
          user_id :: binary(),
          token :: binary(),
          claims :: map(),
          opts :: keyword()
        ) :: {:ok, AccessToken.t()} | {:error, Ecto.Changeset.t()}
  def store_token(user_id, token, claims, opts \\ []) do
    attrs = %{
      user_id: user_id,
      token_hash: hash_token(token),
      jti: claims["jti"],
      token_type: claims["typ"] || "access",
      expires_at: DateTime.from_unix!(claims["exp"]),
      ip_address: Keyword.get(opts, :ip_address),
      user_agent: Keyword.get(opts, :user_agent),
      device_id: Keyword.get(opts, :device_id),
      device_name: Keyword.get(opts, :device_name),
      scopes: Keyword.get(opts, :scopes, []),
      metadata: Keyword.get(opts, :metadata, %{}),
      refresh_token_id: Keyword.get(opts, :refresh_token_id)
    }

    AccessToken.new(attrs)
    |> Repo.insert()
  end

  @doc """
  Stores a refresh token with a reference to its access token.
  """
  @spec store_refresh_token(
          user_id :: binary(),
          token :: binary(),
          claims :: map(),
          access_token_id :: binary(),
          opts :: keyword()
        ) :: {:ok, AccessToken.t()} | {:error, Ecto.Changeset.t()}
  def store_refresh_token(user_id, token, claims, access_token_id, opts \\ []) do
    attrs = %{
      user_id: user_id,
      token_hash: hash_token(token),
      jti: claims["jti"],
      token_type: "refresh",
      expires_at: DateTime.from_unix!(claims["exp"]),
      refresh_token_id: access_token_id,
      ip_address: Keyword.get(opts, :ip_address),
      user_agent: Keyword.get(opts, :user_agent),
      device_id: Keyword.get(opts, :device_id),
      device_name: Keyword.get(opts, :device_name),
      metadata: Keyword.get(opts, :metadata, %{})
    }

    AccessToken.new(attrs)
    |> Repo.insert()
  end

  @doc """
  Checks if a token is revoked by JTI.
  """
  @spec token_revoked?(jti :: binary()) :: boolean()
  def token_revoked?(jti) when is_binary(jti) do
    query =
      from t in AccessToken,
        where: t.jti == ^jti and not is_nil(t.revoked_at),
        select: count()

    Repo.one(query) > 0
  end

  @doc """
  Checks if a token is revoked by token hash.
  """
  @spec token_revoked_by_hash?(token_hash :: binary()) :: boolean()
  def token_revoked_by_hash?(token_hash) when is_binary(token_hash) do
    query =
      from t in AccessToken,
        where: t.token_hash == ^token_hash and not is_nil(t.revoked_at),
        select: count()

    Repo.one(query) > 0
  end

  @doc """
  Validates if a refresh token is still active and valid.
  """
  @spec validate_refresh_token(token :: binary(), user_id :: binary()) ::
          {:ok, AccessToken.t()} | {:error, :token_not_found | :token_revoked | :token_expired}
  def validate_refresh_token(token, user_id) do
    token_hash = hash_token(token)

    query =
      from t in AccessToken,
        where:
          t.token_hash == ^token_hash and
            t.user_id == ^user_id and
            t.token_type == "refresh",
        limit: 1

    case Repo.one(query) do
      nil ->
        {:error, :token_not_found}

      %AccessToken{revoked_at: revoked_at} when not is_nil(revoked_at) ->
        {:error, :token_revoked}

      %AccessToken{} = token ->
        if AccessToken.expired?(token) do
          {:error, :token_expired}
        else
          # Update usage stats
          token
          |> AccessToken.update_usage()
          |> Repo.update()

          {:ok, token}
        end
    end
  end

  @doc """
  Revokes a token by its hash.
  """
  @spec revoke_token(token :: binary(), revoked_by_id :: binary() | nil, reason :: binary() | nil) ::
          {:ok, AccessToken.t()} | {:error, :token_not_found}
  def revoke_token(token, revoked_by_id \\ nil, reason \\ nil) do
    token_hash = hash_token(token)

    query =
      from t in AccessToken,
        where: t.token_hash == ^token_hash and is_nil(t.revoked_at)

    case Repo.one(query) do
      nil ->
        {:error, :token_not_found}

      token ->
        token
        |> AccessToken.revoke(revoked_by_id, reason)
        |> Repo.update()
    end
  end

  @doc """
  Revokes a token by its JTI.
  """
  @spec revoke_token_by_jti(
          jti :: binary(),
          revoked_by_id :: binary() | nil,
          reason :: binary() | nil
        ) ::
          {:ok, AccessToken.t()} | {:error, :token_not_found}
  def revoke_token_by_jti(jti, revoked_by_id \\ nil, reason \\ nil) do
    query =
      from t in AccessToken,
        where: t.jti == ^jti and is_nil(t.revoked_at)

    case Repo.one(query) do
      nil ->
        {:error, :token_not_found}

      token ->
        token
        |> AccessToken.revoke(revoked_by_id, reason)
        |> Repo.update()
    end
  end

  @doc """
  Revokes all tokens for a user.
  """
  @spec revoke_all_user_tokens(
          user_id :: binary(),
          revoked_by_id :: binary() | nil,
          reason :: binary() | nil
        ) ::
          {integer(), nil}
  def revoke_all_user_tokens(user_id, revoked_by_id \\ nil, reason \\ nil) do
    now = DateTime.utc_now()

    query =
      from t in AccessToken,
        where: t.user_id == ^user_id and is_nil(t.revoked_at)

    updates = [
      set: [
        revoked_at: now,
        revoked_by_id: revoked_by_id,
        revoke_reason: reason,
        updated_at: now
      ]
    ]

    Repo.update_all(query, updates)
  end

  @doc """
  Revokes all tokens of a specific type for a user.
  """
  @spec revoke_user_tokens_by_type(
          user_id :: binary(),
          token_type :: binary(),
          revoked_by_id :: binary() | nil,
          reason :: binary() | nil
        ) ::
          {integer(), nil}
  def revoke_user_tokens_by_type(user_id, token_type, revoked_by_id \\ nil, reason \\ nil) do
    now = DateTime.utc_now()

    query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            t.token_type == ^token_type and
            is_nil(t.revoked_at)

    updates = [
      set: [
        revoked_at: now,
        revoked_by_id: revoked_by_id,
        revoke_reason: reason,
        updated_at: now
      ]
    ]

    Repo.update_all(query, updates)
  end

  @doc """
  Gets active tokens for a user.
  """
  @spec get_user_active_tokens(user_id :: binary(), token_type :: binary() | nil) :: [
          AccessToken.t()
        ]
  def get_user_active_tokens(user_id, token_type \\ nil) do
    base_query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            is_nil(t.revoked_at) and
            t.expires_at > ^DateTime.utc_now(),
        order_by: [desc: t.last_used_at, desc: t.inserted_at]

    query =
      if token_type do
        from t in base_query, where: t.token_type == ^token_type
      else
        base_query
      end

    Repo.all(query)
  end

  @doc """
  Gets token by JTI.
  """
  @spec get_token_by_jti(jti :: binary()) :: AccessToken.t() | nil
  def get_token_by_jti(jti) do
    Repo.get_by(AccessToken, jti: jti)
  end

  @doc """
  Gets token by hash.
  """
  @spec get_token_by_hash(token_hash :: binary()) :: AccessToken.t() | nil
  def get_token_by_hash(token_hash) do
    Repo.get_by(AccessToken, token_hash: token_hash)
  end

  @doc """
  Cleans up expired tokens.
  """
  @spec cleanup_expired_tokens() :: {integer(), nil}
  def cleanup_expired_tokens do
    cutoff_date = DateTime.utc_now()

    query =
      from t in AccessToken,
        where: t.expires_at <= ^cutoff_date

    {count, _} = Repo.delete_all(query)

    Logger.info("Cleaned up #{count} expired tokens")
    {count, nil}
  end

  @doc """
  Cleans up revoked tokens older than specified days.
  """
  @spec cleanup_revoked_tokens(days_old :: integer()) :: {integer(), nil}
  def cleanup_revoked_tokens(days_old \\ 30) do
    cutoff_date = DateTime.add(DateTime.utc_now(), -days_old * 24 * 60 * 60, :second)

    query =
      from t in AccessToken,
        where: not is_nil(t.revoked_at) and t.revoked_at <= ^cutoff_date

    {count, _} = Repo.delete_all(query)

    Logger.info("Cleaned up #{count} old revoked tokens")
    {count, nil}
  end

  @doc """
  Gets token statistics for a user.
  """
  @spec get_user_token_stats(user_id :: binary()) :: map()
  def get_user_token_stats(user_id) do
    base_query = from t in AccessToken, where: t.user_id == ^user_id

    active_count =
      from(t in base_query,
        where: is_nil(t.revoked_at) and t.expires_at > ^DateTime.utc_now(),
        select: count()
      )
      |> Repo.one()

    revoked_count =
      from(t in base_query,
        where: not is_nil(t.revoked_at),
        select: count()
      )
      |> Repo.one()

    expired_count =
      from(t in base_query,
        where: is_nil(t.revoked_at) and t.expires_at <= ^DateTime.utc_now(),
        select: count()
      )
      |> Repo.one()

    last_used =
      from(t in base_query,
        where: not is_nil(t.last_used_at),
        select: max(t.last_used_at)
      )
      |> Repo.one()

    %{
      active_tokens: active_count,
      revoked_tokens: revoked_count,
      expired_tokens: expired_count,
      last_used_at: last_used,
      total_tokens: active_count + revoked_count + expired_count
    }
  end

  @doc """
  Lists user devices based on active tokens.
  """
  @spec get_user_devices(user_id :: binary()) :: [map()]
  def get_user_devices(user_id) do
    query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            not is_nil(t.device_id) and
            is_nil(t.revoked_at) and
            t.expires_at > ^DateTime.utc_now(),
        group_by: [t.device_id, t.device_name, t.user_agent],
        select: %{
          device_id: t.device_id,
          device_name: t.device_name,
          user_agent: t.user_agent,
          last_used_at: max(t.last_used_at),
          token_count: count(t.id)
        },
        order_by: [desc: max(t.last_used_at)]

    Repo.all(query)
  end

  @doc """
  Revokes all tokens for a specific device.
  """
  @spec revoke_device_tokens(
          user_id :: binary(),
          device_id :: binary(),
          revoked_by_id :: binary() | nil
        ) ::
          {integer(), nil}
  def revoke_device_tokens(user_id, device_id, revoked_by_id \\ nil) do
    now = DateTime.utc_now()

    query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            t.device_id == ^device_id and
            is_nil(t.revoked_at)

    updates = [
      set: [
        revoked_at: now,
        revoked_by_id: revoked_by_id,
        revoke_reason: "device_revoked",
        updated_at: now
      ]
    ]

    {count, _} = Repo.update_all(query, updates)
    Logger.info("Revoked #{count} tokens for device #{device_id}")

    {count, nil}
  end

  @doc """
  Finds tokens that should be rotated.
  """
  @spec find_tokens_for_rotation(limit :: integer()) :: [AccessToken.t()]
  def find_tokens_for_rotation(limit \\ 100) do
    # Find refresh tokens that are candidates for rotation
    # Based on age (>50% of lifetime) or usage count (>10 uses)

    now = DateTime.utc_now()
    # Calculate 50% of 7 days (typical refresh token lifetime)
    age_threshold = DateTime.add(now, -3 * 24 * 60 * 60, :second)

    query =
      from t in AccessToken,
        where:
          t.token_type == "refresh" and
            is_nil(t.revoked_at) and
            t.expires_at > ^now and
            (t.inserted_at <= ^age_threshold or t.used_count >= 10),
        order_by: [asc: t.inserted_at, desc: t.used_count],
        limit: ^limit

    Repo.all(query)
  end

  @doc """
  Gets security events for token usage analysis.
  """
  @spec get_security_events(user_id :: binary(), opts :: keyword()) :: [map()]
  def get_security_events(user_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    since =
      Keyword.get(opts, :since, DateTime.add(DateTime.utc_now(), -30 * 24 * 60 * 60, :second))

    # Suspicious activity patterns
    query =
      from t in AccessToken,
        where: t.user_id == ^user_id and t.inserted_at >= ^since,
        select: %{
          event_type:
            fragment(
              "CASE 
                WHEN ? IS NOT NULL THEN 'token_revoked'
                WHEN ? = 'refresh' THEN 'refresh_token_used'
                WHEN ? > 0 THEN 'token_used'
                ELSE 'token_created'
               END",
              t.revoked_at,
              t.token_type,
              t.used_count
            ),
          occurred_at:
            fragment(
              "COALESCE(?, ?, ?)",
              t.revoked_at,
              t.last_used_at,
              t.inserted_at
            ),
          ip_address: t.ip_address,
          user_agent: t.user_agent,
          device_id: t.device_id,
          token_type: t.token_type,
          metadata: t.metadata
        },
        order_by: [desc: :occurred_at],
        limit: ^limit

    Repo.all(query)
  end

  @doc """
  Detects potential security threats based on token usage patterns.
  """
  @spec detect_threats(user_id :: binary()) :: [map()]
  def detect_threats(user_id) do
    threats = []

    # Check for multiple active sessions from different IPs
    threats = threats ++ check_multiple_locations(user_id)

    # Check for unusual device activity
    threats = threats ++ check_unusual_devices(user_id)

    # Check for high token usage
    threats = threats ++ check_high_token_usage(user_id)

    threats
  end

  # Private functions

  defp hash_token(token) when is_binary(token) do
    :crypto.hash(@hash_algorithm, token)
    |> Base.encode16(case: :lower)
  end

  defp check_multiple_locations(user_id) do
    # Check for active tokens from multiple IP addresses in last 24 hours
    since = DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second)

    query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            t.last_used_at >= ^since and
            is_nil(t.revoked_at) and
            not is_nil(t.ip_address),
        group_by: t.ip_address,
        select: %{ip_address: t.ip_address, count: count()},
        having: count() > 0

    ips = Repo.all(query)

    if length(ips) > 3 do
      [
        %{
          type: :multiple_locations,
          severity: :medium,
          description: "Active tokens from #{length(ips)} different IP addresses",
          details: %{ip_addresses: Enum.map(ips, & &1.ip_address)},
          detected_at: DateTime.utc_now()
        }
      ]
    else
      []
    end
  end

  defp check_unusual_devices(user_id) do
    # Check for new devices in last 7 days
    since = DateTime.add(DateTime.utc_now(), -7 * 24 * 60 * 60, :second)

    query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            t.inserted_at >= ^since and
            not is_nil(t.device_id),
        group_by: t.device_id,
        select: %{device_id: t.device_id, first_seen: min(t.inserted_at)}

    new_devices = Repo.all(query)

    if length(new_devices) > 2 do
      [
        %{
          type: :new_devices,
          severity: :low,
          description: "#{length(new_devices)} new devices registered in last 7 days",
          details: %{devices: new_devices},
          detected_at: DateTime.utc_now()
        }
      ]
    else
      []
    end
  end

  defp check_high_token_usage(user_id) do
    # Check for tokens with unusually high usage
    query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            t.used_count > 100 and
            is_nil(t.revoked_at),
        select: %{
          jti: t.jti,
          used_count: t.used_count,
          token_type: t.token_type,
          last_used_at: t.last_used_at
        }

    high_usage_tokens = Repo.all(query)

    if length(high_usage_tokens) > 0 do
      [
        %{
          type: :high_token_usage,
          severity: :medium,
          description: "#{length(high_usage_tokens)} tokens with unusually high usage",
          details: %{tokens: high_usage_tokens},
          detected_at: DateTime.utc_now()
        }
      ]
    else
      []
    end
  end
end
