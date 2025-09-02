defmodule BaseAclEx.SharedKernel.CQRS.CommandHandler do
  @moduledoc """
  Base behavior for command handlers.
  Command handlers execute commands and return results.
  """

  @doc """
  Executes the command and returns the result.
  """
  @callback execute(command :: struct()) :: {:ok, any()} | {:error, any()}

  @doc """
  Handles the command asynchronously.
  """
  @callback execute_async(command :: struct()) :: {:ok, pid()} | {:error, any()}

  @optional_callbacks [execute_async: 1]

  defmacro __using__(_opts) do
    quote do
      @behaviour BaseAclEx.SharedKernel.CQRS.CommandHandler
      require Logger

      def execute_async(command) do
        Task.start(fn ->
          case execute(command) do
            {:ok, _result} ->
              Logger.info("Command executed successfully: #{inspect(command.__struct__)}")

            {:error, reason} ->
              Logger.error("Command execution failed: #{inspect(reason)}")
          end
        end)
      end

      defoverridable execute_async: 1
    end
  end
end
