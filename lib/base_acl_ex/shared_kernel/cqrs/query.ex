defmodule BaseAclEx.SharedKernel.CQRS.Query do
  @moduledoc """
  Base behavior for queries in the CQRS pattern.
  Queries represent read operations that don't modify state.
  """
  
  @doc """
  Validates the query parameters.
  Returns {:ok, query} if valid, {:error, errors} otherwise.
  """
  @callback validate(query :: struct()) :: {:ok, struct()} | {:error, any()}
  
  @doc """
  Returns caching configuration for the query.
  """
  @callback cache_config(query :: struct()) :: keyword()
  
  @optional_callbacks [cache_config: 1]
  
  defmacro __using__(_opts) do
    quote do
      @behaviour BaseAclEx.SharedKernel.CQRS.Query
      
      def validate(query) do
        {:ok, query}
      end
      
      def cache_config(_query) do
        [enabled: false]
      end
      
      defoverridable [validate: 1, cache_config: 1]
    end
  end
end