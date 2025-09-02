defmodule BaseAclEx.Infrastructure.Security.Workers.TokenCleanupWorker do
  @moduledoc """
  GenServer worker for cleaning up expired and old revoked tokens.
  Runs periodic cleanup to maintain token store performance.
  """

  use GenServer
  require Logger

  alias BaseAclEx.Infrastructure.Security.Services.TokenStore

  # Run every 6 hours
  @cleanup_interval_ms :timer.hours(6)
  # Keep revoked tokens for 30 days
  @revoked_token_retention_days 30

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Schedule initial cleanup
    schedule_cleanup()

    Logger.info("Token cleanup worker started with #{@cleanup_interval_ms}ms interval")

    {:ok,
     %{
       cleanup_interval: @cleanup_interval_ms,
       revoked_retention_days: @revoked_token_retention_days,
       last_cleanup: nil,
       cleanup_count: 0
     }}
  end

  @impl true
  def handle_info(:cleanup, state) do
    start_time = System.monotonic_time(:millisecond)

    try do
      # Clean up expired tokens
      {expired_count, _} = TokenStore.cleanup_expired_tokens()

      # Clean up old revoked tokens
      {revoked_count, _} = TokenStore.cleanup_revoked_tokens(state.revoked_retention_days)

      total_cleaned = expired_count + revoked_count
      cleanup_time = System.monotonic_time(:millisecond) - start_time

      Logger.info(
        "Token cleanup completed: #{expired_count} expired, #{revoked_count} old revoked, #{cleanup_time}ms"
      )

      # Schedule next cleanup
      schedule_cleanup()

      new_state = %{
        state
        | last_cleanup: DateTime.utc_now(),
          cleanup_count: state.cleanup_count + 1
      }

      {:noreply, new_state}
    rescue
      error ->
        Logger.error("Token cleanup failed: #{inspect(error)}")

        # Reschedule cleanup in 30 minutes on error
        Process.send_after(self(), :cleanup, :timer.minutes(30))

        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      last_cleanup: state.last_cleanup,
      cleanup_count: state.cleanup_count,
      cleanup_interval_ms: state.cleanup_interval,
      revoked_retention_days: state.revoked_retention_days,
      next_cleanup_in_ms: get_next_cleanup_time()
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_call(:force_cleanup, _from, state) do
    send(self(), :cleanup)
    {:reply, :ok, state}
  end

  @doc """
  Forces an immediate cleanup run.
  """
  @spec force_cleanup() :: :ok
  def force_cleanup do
    GenServer.call(__MODULE__, :force_cleanup)
  end

  @doc """
  Gets worker statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Private functions

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  defp get_next_cleanup_time do
    # This is approximate since we don't track when the timer was set
    @cleanup_interval_ms
  end
end
