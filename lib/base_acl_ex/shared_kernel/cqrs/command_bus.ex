defmodule BaseAclEx.SharedKernel.CQRS.CommandBus do
  @moduledoc """
  Command bus for dispatching commands to their handlers.
  Supports middleware pipeline for cross-cutting concerns.
  """

  use GenServer
  require Logger

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Dispatches a command to its handler.
  """
  def dispatch(command) do
    GenServer.call(__MODULE__, {:dispatch, command})
  end

  @doc """
  Dispatches a command asynchronously.
  """
  def dispatch_async(command) do
    GenServer.cast(__MODULE__, {:dispatch_async, command})
  end

  @doc """
  Registers a handler for a command type.
  """
  def register_handler(command_module, handler_module) do
    GenServer.call(__MODULE__, {:register_handler, command_module, handler_module})
  end

  @doc """
  Adds middleware to the pipeline.
  """
  def add_middleware(middleware_module) do
    GenServer.call(__MODULE__, {:add_middleware, middleware_module})
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    state = %{
      handlers: %{},
      middleware: [],
      metrics: %{
        commands_processed: 0,
        commands_failed: 0
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:dispatch, command}, _from, state) do
    result = execute_command_pipeline(command, state)

    new_state = update_metrics(state, result)

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:register_handler, command_module, handler_module}, _from, state) do
    new_handlers = Map.put(state.handlers, command_module, handler_module)
    {:reply, :ok, %{state | handlers: new_handlers}}
  end

  @impl true
  def handle_call({:add_middleware, middleware_module}, _from, state) do
    new_middleware = state.middleware ++ [middleware_module]
    {:reply, :ok, %{state | middleware: new_middleware}}
  end

  @impl true
  def handle_cast({:dispatch_async, command}, state) do
    Task.start(fn ->
      execute_command_pipeline(command, state)
    end)

    {:noreply, state}
  end

  # Private functions

  defp execute_command_pipeline(command, state) do
    with {:ok, command} <- validate_command(command),
         {:ok, handler} <- find_handler(command, state),
         {:ok, command} <- apply_middleware(command, state.middleware, :before),
         {:ok, result} <- execute_handler(handler, command),
         {:ok, result} <- apply_middleware(result, state.middleware, :after) do
      log_command_execution(command, :success)
      publish_domain_events(command, result)

      {:ok, result}
    else
      {:error, reason} = error ->
        log_command_execution(command, :failure, reason)
        error
    end
  end

  defp validate_command(command) do
    if function_exported?(command.__struct__, :validate, 1) do
      command.__struct__.validate(command)
    else
      {:ok, command}
    end
  end

  defp find_handler(command, state) do
    case Map.get(state.handlers, command.__struct__) do
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

  defp execute_handler(handler_module, command) do
    try do
      handler_module.execute(command)
    rescue
      e ->
        Logger.error("Handler execution failed: #{inspect(e)}")
        {:error, :handler_execution_failed}
    end
  end

  defp publish_domain_events(_command, result) do
    # Extract and publish domain events if present
    case result do
      %{domain_events: events} when is_list(events) ->
        Enum.each(events, fn event ->
          Phoenix.PubSub.broadcast(
            BaseAclEx.PubSub,
            "domain_events",
            {:domain_event, event}
          )
        end)

      _ ->
        :ok
    end
  end

  defp log_command_execution(command, status, reason \\ nil) do
    metadata =
      if function_exported?(command.__struct__, :metadata, 1) do
        command.__struct__.metadata(command)
      else
        %{}
      end

    log_entry =
      Map.merge(metadata, %{
        command: command.__struct__ |> Module.split() |> List.last(),
        status: status,
        reason: reason
      })

    case status do
      :success ->
        Logger.info("Command executed", log_entry)

      :failure ->
        Logger.error("Command failed", log_entry)
    end
  end

  defp update_metrics(state, result) do
    case result do
      {:ok, _} ->
        update_in(state.metrics.commands_processed, &(&1 + 1))

      {:error, _} ->
        update_in(state.metrics.commands_failed, &(&1 + 1))
    end
  end
end
