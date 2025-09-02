defmodule BaseAclEx.Infrastructure.Security.Services.TokenRotationService do
  @moduledoc """
  Service for automatic token rotation based on security policies.
  Handles refresh token rotation to enhance security.
  """

  require Logger

  alias BaseAclEx.Infrastructure.Security.Services.TokenStore
  alias BaseAclEx.Infrastructure.Security.Entities.AccessToken
  alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl
  alias BaseAclEx.Repo
  alias BaseAclEx.Accounts.Core.Entities.User

  @doc """
  Performs automatic token rotation for eligible tokens.
  """
  @spec rotate_eligible_tokens(limit :: integer()) :: {:ok, map()}
  def rotate_eligible_tokens(limit \\ 50) do
    start_time = System.monotonic_time(:millisecond)

    tokens_to_rotate = TokenStore.find_tokens_for_rotation(limit)

    results =
      Enum.map(tokens_to_rotate, fn token ->
        case rotate_token(token) do
          {:ok, _new_token} ->
            :rotated

          {:error, reason} ->
            Logger.warning("Failed to rotate token #{token.jti}: #{inspect(reason)}")
            :failed
        end
      end)

    rotated_count = Enum.count(results, &(&1 == :rotated))
    failed_count = Enum.count(results, &(&1 == :failed))
    rotation_time = System.monotonic_time(:millisecond) - start_time

    Logger.info(
      "Token rotation completed: #{rotated_count} rotated, #{failed_count} failed, #{rotation_time}ms"
    )

    {:ok,
     %{
       rotated: rotated_count,
       failed: failed_count,
       total_processed: length(tokens_to_rotate),
       duration_ms: rotation_time
     }}
  end

  @doc """
  Rotates a specific refresh token.
  """
  @spec rotate_token(AccessToken.t()) :: {:ok, AccessToken.t()} | {:error, any()}
  def rotate_token(%AccessToken{token_type: "refresh", user_id: user_id} = old_token) do
    Repo.transaction(fn ->
      with {:ok, user} <- get_user(user_id),
           {:ok, new_token, new_claims} <- generate_new_refresh_token(user),
           {:ok, new_token_record} <- store_new_token(user, new_token, new_claims, old_token),
           {:ok, _revoked_token} <- revoke_old_token(old_token) do
        new_token_record
      else
        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  def rotate_token(%AccessToken{token_type: type}) do
    {:error, "Cannot rotate #{type} token"}
  end

  @doc """
  Forces rotation of all refresh tokens for a user.
  This is useful for security incidents or password changes.
  """
  @spec force_rotate_user_tokens(user_id :: binary(), reason :: binary()) :: {:ok, map()}
  def force_rotate_user_tokens(user_id, reason \\ "security_policy") do
    refresh_tokens = TokenStore.get_user_active_tokens(user_id, "refresh")

    results =
      Enum.map(refresh_tokens, fn token ->
        case rotate_token(token) do
          {:ok, _new_token} -> :rotated
          {:error, _reason} -> :failed
        end
      end)

    rotated_count = Enum.count(results, &(&1 == :rotated))
    failed_count = Enum.count(results, &(&1 == :failed))

    Logger.info("Force rotated #{rotated_count} tokens for user #{user_id}, reason: #{reason}")

    {:ok,
     %{
       rotated: rotated_count,
       failed: failed_count,
       reason: reason
     }}
  end

  @doc """
  Analyzes token rotation patterns and provides recommendations.
  """
  @spec analyze_rotation_patterns(user_id :: binary()) :: map()
  def analyze_rotation_patterns(user_id) do
    thirty_days_ago = DateTime.add(DateTime.utc_now(), -30 * 24 * 60 * 60, :second)

    import Ecto.Query

    # Get rotation statistics
    rotation_query =
      from t in AccessToken,
        where:
          t.user_id == ^user_id and
            t.revoke_reason == "rotated" and
            t.revoked_at >= ^thirty_days_ago,
        select: %{
          rotation_count: count(),
          avg_token_lifetime:
            avg(fragment("EXTRACT(EPOCH FROM (? - ?))", t.revoked_at, t.inserted_at)),
          last_rotation: max(t.revoked_at)
        }

    rotation_stats =
      Repo.one(rotation_query) || %{rotation_count: 0, avg_token_lifetime: 0, last_rotation: nil}

    # Get current active tokens
    active_tokens = TokenStore.get_user_active_tokens(user_id, "refresh")

    recommendations = []

    # Recommend rotation if tokens are old
    recommendations =
      if length(active_tokens) > 0 do
        old_tokens = Enum.filter(active_tokens, &AccessToken.should_rotate?/1)

        if length(old_tokens) > 0 do
          [
            %{
              type: :rotation_needed,
              message: "#{length(old_tokens)} refresh tokens should be rotated",
              priority: :medium
            }
            | recommendations
          ]
        else
          recommendations
        end
      else
        recommendations
      end

    # Recommend security review if too many rotations
    recommendations =
      if rotation_stats.rotation_count > 10 do
        [
          %{
            type: :security_review,
            message:
              "High rotation frequency detected (#{rotation_stats.rotation_count} in 30 days)",
            priority: :high
          }
          | recommendations
        ]
      else
        recommendations
      end

    %{
      rotation_count_30d: rotation_stats.rotation_count,
      avg_token_lifetime_hours:
        if(rotation_stats.avg_token_lifetime,
          do: rotation_stats.avg_token_lifetime / 3600,
          else: 0
        ),
      last_rotation: rotation_stats.last_rotation,
      active_refresh_tokens: length(active_tokens),
      tokens_needing_rotation: Enum.count(active_tokens, &AccessToken.should_rotate?/1),
      recommendations: recommendations
    }
  end

  # Private functions

  defp get_user(user_id) do
    case Repo.get(User, user_id) do
      nil -> {:error, :user_not_found}
      user -> {:ok, user}
    end
  end

  defp generate_new_refresh_token(user) do
    GuardianImpl.encode_and_sign(user, %{},
      token_type: "refresh",
      ttl: {7, :days}
    )
  end

  defp store_new_token(user, new_token, new_claims, old_token) do
    opts = [
      ip_address: old_token.ip_address,
      user_agent: old_token.user_agent,
      device_id: old_token.device_id,
      device_name: old_token.device_name,
      metadata: Map.put(old_token.metadata || %{}, "rotated_from", old_token.jti)
    ]

    TokenStore.store_token(user.id, new_token, new_claims, opts)
  end

  defp revoke_old_token(old_token) do
    old_token
    |> AccessToken.revoke(nil, "rotated")
    |> Repo.update()
  end
end
