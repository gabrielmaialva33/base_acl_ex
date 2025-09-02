defmodule BaseAclEx.SharedKernel.CQRS.QueryBus do
  @moduledoc """
  Query bus for dispatching queries to their handlers.
  Supports caching and middleware pipeline.
  """

  use GenServer
  require Logger
  import Cachex.Spec

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Executes a query and returns the result.
  """
  def execute(query) do
    GenServer.call(__MODULE__, {:execute, query})
  end

  @doc """
  Registers a handler for a query type.
  """
  def register_handler(query_module, handler_module) do
    GenServer.call(__MODULE__, {:register_handler, query_module, handler_module})
  end

  @doc """
  Adds middleware to the pipeline.
  """
  def add_middleware(middleware_module) do
    GenServer.call(__MODULE__, {:add_middleware, middleware_module})
  end

  @doc """
  Gets query execution metrics.
  """
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Start query cache if not already started
    Cachex.start_link(:query_cache,
      stats: true,
      expiration:
        expiration(
          default: :timer.minutes(5),
          interval: :timer.minutes(1),
          lazy: true
        )
    )

    state = %{
      handlers: %{},
      middleware: [],
      metrics: %{
        queries_executed: 0,
        cache_hits: 0,
        cache_misses: 0,
        query_errors: 0
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:execute, query}, _from, state) do
    result = execute_query_pipeline(query, state)

    new_state = update_metrics(state, result, query)

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:register_handler, query_module, handler_module}, _from, state) do
    new_handlers = Map.put(state.handlers, query_module, handler_module)
    {:reply, :ok, %{state | handlers: new_handlers}}
  end

  @impl true
  def handle_call({:add_middleware, middleware_module}, _from, state) do
    new_middleware = state.middleware ++ [middleware_module]
    {:reply, :ok, %{state | middleware: new_middleware}}
  end

  @impl true
  def handle_call(:get_metrics, _from, state) do
    {:reply, state.metrics, state}
  end

  # Private functions

  defp execute_query_pipeline(query, state) do
    with {:ok, query} <- validate_query(query),
         {:ok, handler} <- find_handler(query, state),
         {:ok, query} <- apply_middleware(query, state.middleware, :before),
         {:ok, result} <- execute_with_cache(handler, query, state),
         {:ok, result} <- apply_middleware(result, state.middleware, :after) do
      log_query_execution(query, :success)
      {:ok, result}
    else
      {:error, reason} = error ->
        log_query_execution(query, :failure, reason)
        error
    end
  end

  defp validate_query(query) do
    if function_exported?(query.__struct__, :validate, 1) do
      query.__struct__.validate(query)
    else
      {:ok, query}
    end
  end

  defp find_handler(query, state) do
    case Map.get(state.handlers, query.__struct__) do
      nil -> {:error, :handler_not_found}
      handler -> {:ok, handler}
    end
  end

  defp apply_middleware(data, [], _phase), do: {:ok, data}

  defp apply_middleware(data, [middleware | rest], phase) do
    case apply(middleware, phase, [data]) do
      {:ok, new_data} -> apply_middleware(new_data, rest, phase)
      error -> error
    end
  end

  defp execute_with_cache(handler_module, query, state) do
    cache_config = get_cache_config(query)

    if cache_config[:enabled] do
      cache_key = generate_cache_key(query)

      case Cachex.get(:query_cache, cache_key) do
        {:ok, nil} ->
          # Cache miss
          GenServer.cast(self(), {:update_cache_miss, 1})

          result = handler_module.execute(query)

          if match?({:ok, _}, result) do
            ttl = cache_config[:ttl] || :timer.minutes(5)
            Cachex.put(:query_cache, cache_key, result, ttl: ttl)
          end

          result

        {:ok, cached_result} ->
          # Cache hit
          GenServer.cast(self(), {:update_cache_hit, 1})
          cached_result

        _ ->
          handler_module.execute(query)
      end
    else
      handler_module.execute(query)
    end
  end

  @impl true
  def handle_cast({:update_cache_hit, count}, state) do
    new_state = update_in(state.metrics.cache_hits, &(&1 + count))
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:update_cache_miss, count}, state) do
    new_state = update_in(state.metrics.cache_misses, &(&1 + count))
    {:noreply, new_state}
  end

  defp get_cache_config(query) do
    if function_exported?(query.__struct__, :cache_config, 1) do
      query.__struct__.cache_config(query)
    else
      [enabled: false]
    end
  end

  defp generate_cache_key(query) do
    query
    |> Map.from_struct()
    |> :erlang.phash2()
    |> to_string()
  end

  defp log_query_execution(query, status, reason \\ nil) do
    log_entry = %{
      query: query.__struct__ |> Module.split() |> List.last(),
      status: status,
      reason: reason
    }

    case status do
      :success ->
        Logger.debug("Query executed", log_entry)

      :failure ->
        Logger.error("Query failed", log_entry)
    end
  end

  defp update_metrics(state, result, _query) do
    case result do
      {:ok, _} ->
        update_in(state.metrics.queries_executed, &(&1 + 1))

      {:error, _} ->
        update_in(state.metrics.query_errors, &(&1 + 1))
    end
  end
end
