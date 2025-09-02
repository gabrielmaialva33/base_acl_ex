defmodule BaseAclEx.Infrastructure.Security.Telemetry.RateLimiterTelemetry do
  @moduledoc """
  Telemetry event handler for rate limiting system.

  Provides monitoring, alerting, and metrics collection for rate limiting events.
  Integrates with existing telemetry infrastructure.
  """

  require Logger

  @doc """
  Attaches telemetry handlers for rate limiting events.

  Should be called during application startup to register all handlers.
  """
  def attach_handlers do
    events = [
      [:base_acl_ex, :rate_limiter, :allowed],
      [:base_acl_ex, :rate_limiter, :blocked],
      [:base_acl_ex, :rate_limiter, :cache, :cleanup]
    ]

    :telemetry.attach_many(
      "rate-limiter-telemetry",
      events,
      &handle_event/4,
      nil
    )
  end

  @doc """
  Handles rate limiting telemetry events.
  """
  def handle_event([:base_acl_ex, :rate_limiter, :allowed], measurements, metadata, _config) do
    Logger.debug("Rate limit allowed", Map.merge(measurements, metadata))

    # Increment allowed requests counter
    :telemetry.execute(
      [:base_acl_ex, :rate_limiter, :requests, :allowed],
      %{count: 1},
      metadata
    )
  end

  def handle_event([:base_acl_ex, :rate_limiter, :blocked], measurements, metadata, _config) do
    Logger.warning("Rate limit blocked", Map.merge(measurements, metadata))

    # Increment blocked requests counter
    :telemetry.execute(
      [:base_acl_ex, :rate_limiter, :requests, :blocked],
      %{count: 1},
      metadata
    )

    # Check if this IP/user should trigger an alert
    maybe_trigger_alert(metadata)
  end

  def handle_event(
        [:base_acl_ex, :rate_limiter, :cache, :cleanup],
        measurements,
        metadata,
        _config
      ) do
    Logger.debug("Rate limiter cache cleanup", Map.merge(measurements, metadata))

    # Track cache health metrics
    if measurements[:eviction_count] && measurements[:eviction_count] > 1000 do
      Logger.warning("High rate limiter cache evictions", measurements)
    end
  end

  @doc """
  Gets rate limiting metrics for the current period.

  Returns a map with:
  - total_allowed: Number of allowed requests
  - total_blocked: Number of blocked requests
  - top_blocked_ips: Most frequently blocked IPs
  - top_blocked_users: Most frequently blocked users
  """
  def get_metrics(period_minutes \\ 60) do
    # This would integrate with your metrics collection system
    # For now, we'll return placeholder metrics
    %{
      period_minutes: period_minutes,
      total_allowed: get_counter_value(:allowed),
      total_blocked: get_counter_value(:blocked),
      block_rate: calculate_block_rate(),
      top_blocked_identifiers: get_top_blocked_identifiers(),
      cache_stats: get_cache_metrics()
    }
  end

  @doc """
  Checks if rate limiting system is healthy.

  Returns health status with any issues detected.
  """
  def health_check do
    cache_healthy = cache_health_check()
    block_rate = calculate_block_rate()

    issues = []

    issues =
      if not cache_healthy do
        ["Cache not responding" | issues]
      else
        issues
      end

    issues =
      if block_rate > 0.5 do
        ["High block rate: #{Float.round(block_rate * 100, 1)}%" | issues]
      else
        issues
      end

    case issues do
      [] ->
        %{
          status: :healthy,
          message: "Rate limiting system operating normally",
          metrics: %{
            cache_healthy: cache_healthy,
            block_rate: block_rate
          }
        }

      issues ->
        %{
          status: :degraded,
          message: "Rate limiting system has issues",
          issues: issues,
          metrics: %{
            cache_healthy: cache_healthy,
            block_rate: block_rate
          }
        }
    end
  end

  # Private functions

  defp maybe_trigger_alert(metadata) do
    identifier = metadata[:identifier]
    endpoint = metadata[:endpoint]

    # Simple alert logic - could be enhanced with more sophisticated rules
    cond do
      String.contains?(identifier, "192.168.") ->
        # Internal IP being blocked - might indicate misconfiguration
        Logger.warning("Internal IP blocked by rate limiter", metadata)

      endpoint && String.contains?(endpoint, "/auth/") ->
        # Auth endpoint being blocked - potential brute force
        Logger.warning("Authentication endpoint rate limited - possible attack", metadata)

      true ->
        :ok
    end
  end

  defp get_counter_value(type) do
    # This would integrate with your metrics system (Prometheus, StatsD, etc.)
    # For now return 0 as placeholder
    0
  end

  defp calculate_block_rate do
    # Calculate the ratio of blocked to total requests
    # This would use actual metrics from your monitoring system
    0.0
  end

  defp get_top_blocked_identifiers do
    # Returns list of most frequently blocked identifiers
    # This would query your metrics system
    []
  end

  defp get_cache_metrics do
    case BaseAclEx.Infrastructure.Security.Cache.RateLimiterCache.get_stats() do
      stats when is_map(stats) ->
        %{
          hit_rate: calculate_hit_rate(stats),
          size: Map.get(stats, :miss_count, 0) + Map.get(stats, :hit_count, 0),
          evictions: Map.get(stats, :eviction_count, 0)
        }

      _ ->
        %{hit_rate: 0.0, size: 0, evictions: 0}
    end
  end

  defp calculate_hit_rate(stats) do
    hits = Map.get(stats, :hit_count, 0)
    misses = Map.get(stats, :miss_count, 0)
    total = hits + misses

    if total > 0 do
      hits / total
    else
      0.0
    end
  end

  defp cache_health_check do
    try do
      case Cachex.ping(:rate_limiter_cache) do
        {:ok, :pong} -> true
        _ -> false
      end
    rescue
      _ -> false
    end
  end
end
