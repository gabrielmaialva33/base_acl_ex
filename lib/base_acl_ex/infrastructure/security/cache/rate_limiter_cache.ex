defmodule BaseAclEx.Infrastructure.Security.Cache.RateLimiterCache do
  @moduledoc """
  Dedicated cache configuration and management for rate limiting.

  Provides a high-performance, fault-tolerant cache specifically for rate limiting
  with appropriate expiration policies and monitoring.
  """

  use GenServer
  require Logger

  @cache_name :rate_limiter_cache
  # Max entries in cache
  @default_limit 100_000
  # 5 minutes
  @cleanup_interval 300_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    limit = Keyword.get(opts, :limit, @default_limit)

    # Start the cache with appropriate policies
    cache_opts = [
      # Default expiration - entries expire after 1 hour
      expiration: [
        default: :timer.hours(1),
        lazy: true
      ],
      # Size limit - LRU eviction when limit reached  
      limit: [
        size: limit,
        policy: :lru,
        reclaim: 0.1
      ],
      # Statistics tracking for monitoring
      stats: true
    ]

    case Cachex.start_link(@cache_name, cache_opts) do
      {:ok, _pid} ->
        Logger.info("Rate limiter cache started successfully")

        # Schedule periodic cleanup
        schedule_cleanup()

        {:ok, %{cache_name: @cache_name, limit: limit}}

      {:error, reason} ->
        Logger.error("Failed to start rate limiter cache: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_info(:cleanup, state) do
    perform_cleanup()
    schedule_cleanup()
    {:noreply, state}
  end

  @doc """
  Returns cache statistics for monitoring.
  """
  def get_stats do
    case Cachex.stats(@cache_name) do
      {:ok, stats} -> stats
      {:error, _} -> %{}
    end
  end

  @doc """
  Clears all rate limit entries (admin operation).
  """
  def clear_all do
    Cachex.clear(@cache_name)
  end

  @doc """
  Gets cache size information.
  """
  def size_info do
    %{
      size: Cachex.size!(@cache_name),
      memory: get_memory_usage()
    }
  end

  # Private functions



  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp perform_cleanup do
    try do
      # Force cleanup of expired entries
      Cachex.purge(@cache_name)

      stats = get_stats()
      Logger.debug("Rate limiter cache cleanup completed", stats)

      # Emit telemetry for monitoring
      :telemetry.execute(
        [:base_acl_ex, :rate_limiter, :cache, :cleanup],
        stats,
        %{cache_name: @cache_name}
      )
    rescue
      error ->
        Logger.warning("Rate limiter cache cleanup failed: #{inspect(error)}")
    end
  end

  defp get_memory_usage do
    try do
      case Cachex.inspect(@cache_name, :memory) do
        {:ok, memory} -> memory
        _ -> 0
      end
    rescue
      _ -> 0
    end
  end
end
