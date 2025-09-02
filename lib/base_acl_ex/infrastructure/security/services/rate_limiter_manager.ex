defmodule BaseAclEx.Infrastructure.Security.Services.RateLimiterManager do
  @moduledoc """
  Administrative management interface for rate limiting system.

  Provides tools for monitoring, managing, and configuring rate limits
  including statistics, cache management, and allowlist operations.
  """

  alias BaseAclEx.Infrastructure.Security.Cache.RateLimiterCache
  alias BaseAclEx.Infrastructure.Security.Services.RateLimiter

  @cache_name :rate_limiter_cache

  @doc """
  Gets comprehensive statistics about the rate limiting system.
  """
  def get_system_stats do
    cache_stats = RateLimiterCache.get_stats()
    size_info = RateLimiterCache.size_info()

    %{
      cache: %{
        size: size_info.size,
        memory_bytes: size_info.memory,
        hits: Map.get(cache_stats, :hit_count, 0),
        misses: Map.get(cache_stats, :miss_count, 0),
        evictions: Map.get(cache_stats, :eviction_count, 0)
      },
      config: %{
        enabled: Application.get_env(:base_acl_ex, :rate_limiting_enabled, true),
        logging_enabled: Application.get_env(:base_acl_ex, :rate_limiting_log_enabled, false)
      },
      uptime: get_cache_uptime()
    }
  end

  @doc """
  Lists all active rate limits with current status.

  Options:
  - limit: Maximum number of entries to return (default: 100)
  - sort_by: :requests | :remaining | :identifier (default: :requests)
  """
  def list_active_limits(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    sort_by = Keyword.get(opts, :sort_by, :requests)

    case Cachex.keys(@cache_name) do
      {:ok, keys} ->
        keys
        |> Enum.take(limit)
        |> Enum.map(&get_limit_info/1)
        |> Enum.filter(&(&1 != nil))
        |> sort_limits(sort_by)

      {:error, _reason} ->
        []
    end
  end

  @doc """
  Gets detailed information about a specific rate limit.
  """
  def get_limit_details(identifier) do
    case Cachex.get(@cache_name, identifier) do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, rate_limit} ->
        {:ok,
         %{
           identifier: rate_limit.identifier,
           current_requests: length(rate_limit.requests),
           max_requests: rate_limit.max_requests,
           remaining: max(0, rate_limit.max_requests - length(rate_limit.requests)),
           window_ms: rate_limit.window_ms,
           reset_time: calculate_reset_time(rate_limit),
           exceeded: length(rate_limit.requests) >= rate_limit.max_requests,
           request_timestamps: rate_limit.requests
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Removes rate limit for specific identifier (admin operation).
  """
  def remove_limit(identifier) do
    RateLimiter.reset_rate_limit(identifier)
  end

  @doc """
  Removes all rate limits (emergency operation).
  """
  def clear_all_limits do
    RateLimiterCache.clear_all()
  end

  @doc """
  Gets rate limits that are currently blocking requests.
  """
  def get_blocked_identifiers do
    case Cachex.keys(@cache_name) do
      {:ok, keys} ->
        keys
        |> Enum.map(&get_limit_info/1)
        |> Enum.filter(fn
          nil -> false
          info -> info.exceeded
        end)

      {:error, _reason} ->
        []
    end
  end

  @doc """
  Finds rate limits by pattern (useful for IP ranges or user patterns).
  """
  def find_limits_by_pattern(pattern) do
    case Cachex.keys(@cache_name) do
      {:ok, keys} ->
        keys
        |> Enum.filter(&String.contains?(&1, pattern))
        |> Enum.map(&get_limit_info/1)
        |> Enum.filter(&(&1 != nil))

      {:error, _reason} ->
        []
    end
  end

  @doc """
  Exports rate limiting data for analysis.
  """
  def export_data(format \\ :json) do
    case list_active_limits(limit: :infinity) do
      [] ->
        case format do
          :json -> "{\"limits\": []}"
          :csv -> "identifier,current_requests,max_requests,remaining,exceeded\n"
        end

      limits ->
        case format do
          :json ->
            Jason.encode!(%{
              exported_at: DateTime.utc_now(),
              limits: limits,
              stats: get_system_stats()
            })

          :csv ->
            headers = "identifier,current_requests,max_requests,remaining,exceeded\n"

            rows =
              Enum.map(limits, fn limit ->
                "#{limit.identifier},#{limit.current_requests},#{limit.max_requests},#{limit.remaining},#{limit.exceeded}"
              end)

            headers <> Enum.join(rows, "\n")
        end
    end
  end

  # Private functions

  defp get_limit_info(identifier) do
    case Cachex.get(@cache_name, identifier) do
      {:ok, nil} ->
        nil

      {:ok, rate_limit} ->
        %{
          identifier: identifier,
          current_requests: length(rate_limit.requests),
          max_requests: rate_limit.max_requests,
          remaining: max(0, rate_limit.max_requests - length(rate_limit.requests)),
          window_ms: rate_limit.window_ms,
          reset_time: calculate_reset_time(rate_limit),
          exceeded: length(rate_limit.requests) >= rate_limit.max_requests,
          last_request: Enum.max(rate_limit.requests, fn -> 0 end)
        }

      {:error, _} ->
        nil
    end
  end

  defp sort_limits(limits, sort_by) do
    case sort_by do
      :requests -> Enum.sort_by(limits, & &1.current_requests, :desc)
      :remaining -> Enum.sort_by(limits, & &1.remaining, :asc)
      :identifier -> Enum.sort_by(limits, & &1.identifier)
      _ -> limits
    end
  end

  defp calculate_reset_time(rate_limit) do
    case rate_limit.requests do
      [] ->
        0

      requests ->
        oldest_request = Enum.min(requests)
        reset_at = oldest_request + rate_limit.window_ms
        max(0, div(reset_at - System.system_time(:millisecond), 1000))
    end
  end

  defp get_cache_uptime do
    # Simple uptime calculation based on when the application started
    case :application.get_key(:base_acl_ex, :started_at) do
      {:ok, start_time} ->
        System.system_time(:second) - start_time

      :undefined ->
        0
    end
  end
end
