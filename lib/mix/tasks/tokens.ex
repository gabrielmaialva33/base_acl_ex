defmodule Mix.Tasks.Tokens do
  @moduledoc """
  Mix tasks for token management operations.

  Available commands:

      mix tokens.cleanup                    # Clean up expired and old revoked tokens
      mix tokens.rotate [--limit=N]         # Rotate eligible refresh tokens
      mix tokens.revoke --user=EMAIL        # Revoke all tokens for a user
      mix tokens.stats [--user=EMAIL]       # Show token statistics
      mix tokens.threats --user=EMAIL       # Analyze security threats for a user
  """

  use Mix.Task

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Infrastructure.Security.Services.{TokenRotationService, TokenStore}
  alias BaseAclEx.Infrastructure.Security.Workers.TokenCleanupWorker
  alias BaseAclEx.Repo

  @requirements ["app.start"]

  def run(["cleanup"]) do
    Mix.shell().info("Starting token cleanup...")

    {expired_count, _} = TokenStore.cleanup_expired_tokens()
    {revoked_count, _} = TokenStore.cleanup_revoked_tokens()

    Mix.shell().info("Cleanup completed:")
    Mix.shell().info("  - Expired tokens removed: #{expired_count}")
    Mix.shell().info("  - Old revoked tokens removed: #{revoked_count}")
  end

  def run(["rotate" | args]) do
    {parsed, _, _} = OptionParser.parse(args, strict: [limit: :integer])
    limit = Keyword.get(parsed, :limit, 50)

    Mix.shell().info("Starting token rotation (limit: #{limit})...")

    {:ok, result} = TokenRotationService.rotate_eligible_tokens(limit)

    Mix.shell().info("Rotation completed:")
    Mix.shell().info("  - Tokens rotated: #{result.rotated}")
    Mix.shell().info("  - Failed rotations: #{result.failed}")
    Mix.shell().info("  - Duration: #{result.duration_ms}ms")
  end

  def run(["revoke" | args]) do
    {parsed, _, _} = OptionParser.parse(args, strict: [user: :string])

    case Keyword.get(parsed, :user) do
      nil ->
        Mix.shell().error("--user=EMAIL is required")

      email ->
        case find_user_by_email(email) do
          nil ->
            Mix.shell().error("User not found: #{email}")

          user ->
            {count, _} = TokenStore.revoke_all_user_tokens(user.id, nil, "admin_revocation")
            Mix.shell().info("Revoked #{count} tokens for user: #{email}")
        end
    end
  end

  def run(["stats" | args]) do
    {parsed, _, _} = OptionParser.parse(args, strict: [user: :string])

    case Keyword.get(parsed, :user) do
      nil ->
        # Global statistics
        show_global_stats()

      email ->
        case find_user_by_email(email) do
          nil ->
            Mix.shell().error("User not found: #{email}")

          user ->
            show_user_stats(user)
        end
    end
  end

  def run(["threats" | args]) do
    {parsed, _, _} = OptionParser.parse(args, strict: [user: :string])

    case Keyword.get(parsed, :user) do
      nil ->
        Mix.shell().error("--user=EMAIL is required")

      email ->
        case find_user_by_email(email) do
          nil ->
            Mix.shell().error("User not found: #{email}")

          user ->
            threats = TokenStore.detect_threats(user.id)
            show_threats(email, threats)
        end
    end
  end

  def run(["worker_stats"]) do
    stats = TokenCleanupWorker.get_stats()

    Mix.shell().info("Token Cleanup Worker Statistics:")
    Mix.shell().info("  - Last cleanup: #{stats.last_cleanup || "Never"}")
    Mix.shell().info("  - Cleanup count: #{stats.cleanup_count}")
    Mix.shell().info("  - Cleanup interval: #{stats.cleanup_interval_ms / 1000 / 60} minutes")
    Mix.shell().info("  - Retention period: #{stats.revoked_retention_days} days")
  end

  def run(args) do
    Mix.shell().error("Unknown command: #{inspect(args)}")
    Mix.shell().info(@moduledoc)
  end

  # Private functions

  defp find_user_by_email(email) do
    Repo.get_by(User, email: String.downcase(email))
  end

  defp show_global_stats do
    import Ecto.Query

    # Global token statistics
    total_query =
      from t in BaseAclEx.Infrastructure.Security.Entities.AccessToken, select: count()

    active_query =
      from t in BaseAclEx.Infrastructure.Security.Entities.AccessToken,
        where: is_nil(t.revoked_at) and t.expires_at > ^DateTime.utc_now(),
        select: count()

    revoked_query =
      from t in BaseAclEx.Infrastructure.Security.Entities.AccessToken,
        where: not is_nil(t.revoked_at),
        select: count()

    expired_query =
      from t in BaseAclEx.Infrastructure.Security.Entities.AccessToken,
        where: is_nil(t.revoked_at) and t.expires_at <= ^DateTime.utc_now(),
        select: count()

    total = Repo.one(total_query)
    active = Repo.one(active_query)
    revoked = Repo.one(revoked_query)
    expired = Repo.one(expired_query)

    Mix.shell().info("Global Token Statistics:")
    Mix.shell().info("  - Total tokens: #{total}")
    Mix.shell().info("  - Active tokens: #{active}")
    Mix.shell().info("  - Revoked tokens: #{revoked}")
    Mix.shell().info("  - Expired tokens: #{expired}")
  end

  defp show_user_stats(user) do
    stats = TokenStore.get_user_token_stats(user.id)
    devices = TokenStore.get_user_devices(user.id)

    Mix.shell().info("Token Statistics for #{user.email}:")
    Mix.shell().info("  - Active tokens: #{stats.active_tokens}")
    Mix.shell().info("  - Revoked tokens: #{stats.revoked_tokens}")
    Mix.shell().info("  - Expired tokens: #{stats.expired_tokens}")
    Mix.shell().info("  - Last used: #{stats.last_used_at || "Never"}")
    Mix.shell().info("  - Device count: #{length(devices)}")

    if length(devices) > 0 do
      Mix.shell().info("\nActive Devices:")

      Enum.each(devices, fn device ->
        Mix.shell().info("  - #{device.device_name} (#{device.device_id})")
        Mix.shell().info("    Last used: #{device.last_used_at}")
        Mix.shell().info("    Tokens: #{device.token_count}")
      end)
    end
  end

  defp show_threats(email, threats) do
    Mix.shell().info("Security Threat Analysis for #{email}:")

    if Enum.empty?(threats) do
      Mix.shell().info("  No threats detected.")
    else
      Enum.each(threats, fn threat ->
        severity_color =
          case threat.severity do
            :low -> :green
            :medium -> :yellow
            :high -> :red
            :critical -> [:red, :bright]
          end

        Mix.shell().info([
          severity_color,
          "  [#{String.upcase(to_string(threat.severity))}] #{threat.description}"
        ])

        if threat.details do
          Mix.shell().info("    Details: #{inspect(threat.details)}")
        end

        Mix.shell().info("    Detected: #{threat.detected_at}")
      end)
    end
  end
end
