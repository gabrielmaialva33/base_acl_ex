defmodule BaseAclEx.SharedKernel.CQRS.Command do
  @moduledoc """
  Base behavior for commands in the CQRS pattern.
  Commands represent write operations that modify state.
  """
  
  @doc """
  Validates the command before execution.
  Returns {:ok, command} if valid, {:error, errors} otherwise.
  """
  @callback validate(command :: struct()) :: {:ok, struct()} | {:error, any()}
  
  @doc """
  Returns metadata for the command (for auditing/tracing).
  """
  @callback metadata(command :: struct()) :: map()
  
  @optional_callbacks [metadata: 1]
  
  defmacro __using__(_opts) do
    quote do
      @behaviour BaseAclEx.SharedKernel.CQRS.Command
      
      def validate(command) do
        {:ok, command}
      end
      
      def metadata(command) do
        %{
          command_type: __MODULE__ |> Module.split() |> List.last(),
          timestamp: DateTime.utc_now()
        }
      end
      
      defoverridable [validate: 1, metadata: 1]
    end
  end
end