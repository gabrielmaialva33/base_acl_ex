defmodule Mix.Tasks.RateLimiter do
  @moduledoc """
  Mix tasks for managing the rate limiting system.

  ## Available commands:

      mix rate_limiter.stats              # Show system statistics
      mix rate_limiter.list               # List active rate limits
      mix rate_limiter.clear <identifier> # Clear specific rate limit
      mix rate_limiter.clear_all          # Clear all rate limits
      mix rate_limiter.health             # Check system health
      mix rate_limiter.export [--format csv|json] # Export data
  """

  use Mix.Task

  alias BaseAclEx.Infrastructure.Security.Services.RateLimiterManager
  alias BaseAclEx.Infrastructure.Security.Telemetry.RateLimiterTelemetry

  @shortdoc "Manage rate limiting system"

  def run(["stats"]) do
    start_app()

    stats = RateLimiterManager.get_system_stats()

    Mix.shell().info("Rate Limiter System Statistics")
    Mix.shell().info("=" <> String.duplicate("=", 35))
    Mix.shell().info("")

    Mix.shell().info("Configuration:")
    Mix.shell().info("  Enabled: #{stats.config.enabled}")
    Mix.shell().info("  Logging: #{stats.config.logging_enabled}")
    Mix.shell().info("")

    Mix.shell().info("Cache Statistics:")
    Mix.shell().info("  Size: #{stats.cache.size} entries")
    Mix.shell().info("  Memory: #{format_bytes(stats.cache.memory_bytes)}")
    Mix.shell().info("  Hits: #{stats.cache.hits}")
    Mix.shell().info("  Misses: #{stats.cache.misses}")
    Mix.shell().info("  Evictions: #{stats.cache.evictions}")
    Mix.shell().info("")

    Mix.shell().info("Uptime: #{format_duration(stats.uptime)}")
  end

  def run(["list"]) do
    start_app()

    limits = RateLimiterManager.list_active_limits(limit: 50)

    if Enum.empty?(limits) do
      Mix.shell().info("No active rate limits found.")
    else
      Mix.shell().info("Active Rate Limits")
      Mix.shell().info("=" <> String.duplicate("=", 25))
      Mix.shell().info("")

      format_string = "~-40s ~8s ~8s ~8s ~8s"

      Mix.shell().info(
        :io_lib.format(
          format_string,
          ["Identifier", "Current", "Max", "Remain", "Blocked"]
        )
      )

      Mix.shell().info(String.duplicate("-", 85))

      for limit <- limits do
        Mix.shell().info(
          :io_lib.format(format_string, [
            String.slice(limit.identifier, 0, 38),
            limit.current_requests,
            limit.max_requests,
            limit.remaining,
            if(limit.exceeded, do: "YES", else: "NO")
          ])
        )
      end

      Mix.shell().info("")
      Mix.shell().info("Total: #{length(limits)} active limits")
    end
  end

  def run(["clear", identifier]) do
    start_app()

    case RateLimiterManager.get_limit_details(identifier) do
      {:ok, _} ->
        RateLimiterManager.remove_limit(identifier)
        Mix.shell().info("Rate limit cleared for: #{identifier}")

      {:error, :not_found} ->
        Mix.shell().error("Rate limit not found for identifier: #{identifier}")
    end
  end

  def run(["clear_all"]) do
    start_app()

    Mix.shell().info("This will clear ALL active rate limits.")

    if Mix.shell().yes?("Are you sure you want to continue?") do
      RateLimiterManager.clear_all_limits()
      Mix.shell().info("All rate limits cleared successfully.")
    else
      Mix.shell().info("Operation cancelled.")
    end
  end

  def run(["health"]) do
    start_app()

    health = RateLimiterTelemetry.health_check()

    Mix.shell().info("Rate Limiter Health Check")
    Mix.shell().info("=" <> String.duplicate("=", 30))
    Mix.shell().info("")

    status_color =
      case health.status do
        :healthy -> :green
        :degraded -> :yellow
        :unhealthy -> :red
      end

    Mix.shell().info([
      :bright,
      status_color,
      "Status: #{String.upcase(to_string(health.status))}"
    ])

    Mix.shell().info("Message: #{health.message}")

    if Map.has_key?(health, :issues) do
      Mix.shell().info("")
      Mix.shell().info("Issues:")

      for issue <- health.issues do
        Mix.shell().info("  - #{issue}")
      end
    end

    Mix.shell().info("")
    Mix.shell().info("Metrics:")
    Mix.shell().info("  Cache Healthy: #{health.metrics.cache_healthy}")
    Mix.shell().info("  Block Rate: #{Float.round(health.metrics.block_rate * 100, 2)}%")
  end

  def run(["export" | args]) do
    start_app()

    {opts, _, _} = OptionParser.parse(args, strict: [format: :string])

    format =
      case Keyword.get(opts, :format, "json") do
        "csv" -> :csv
        _ -> :json
      end

    data = RateLimiterManager.export_data(format)

    filename =
      case format do
        :csv -> "rate_limits_#{Date.utc_today()}.csv"
        :json -> "rate_limits_#{Date.utc_today()}.json"
      end

    File.write!(filename, data)
    Mix.shell().info("Rate limiting data exported to: #{filename}")
  end

  def run(_) do
    Mix.shell().info(@moduledoc)
  end

  # Private functions

  defp start_app do
    Mix.Task.run("app.start")
  end

  defp format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp format_bytes(bytes) when bytes < 1024 * 1024, do: "#{Float.round(bytes / 1024, 1)} KB"
  defp format_bytes(bytes), do: "#{Float.round(bytes / (1024 * 1024), 1)} MB"

  defp format_duration(seconds) when seconds < 60, do: "#{seconds} seconds"

  defp format_duration(seconds) when seconds < 3600 do
    minutes = div(seconds, 60)
    "#{minutes} minutes"
  end

  defp format_duration(seconds) do
    hours = div(seconds, 3600)
    minutes = div(rem(seconds, 3600), 60)
    "#{hours}h #{minutes}m"
  end
end
