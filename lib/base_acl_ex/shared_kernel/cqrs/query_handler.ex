defmodule BaseAclEx.SharedKernel.CQRS.QueryHandler do
  @moduledoc """
  Base behavior for query handlers.
  Query handlers execute queries and return data.
  """

  @doc """
  Executes the query and returns the result.
  """
  @callback execute(query :: struct()) :: {:ok, any()} | {:error, any()}

  @doc """
  Executes the query with caching support.
  """
  @callback execute_with_cache(query :: struct()) :: {:ok, any()} | {:error, any()}

  @optional_callbacks [execute_with_cache: 1]

  defmacro __using__(_opts) do
    quote do
      @behaviour BaseAclEx.SharedKernel.CQRS.QueryHandler

      def execute_with_cache(query) do
        cache_config = query.__struct__.cache_config(query)

        if Keyword.get(cache_config, :enabled, false) do
          execute_with_cache_enabled(query, cache_config)
        else
          execute(query)
        end
      end

      defp execute_with_cache_enabled(query, cache_config) do
        cache_key = generate_cache_key(query)

        case Cachex.get(:query_cache, cache_key) do
          {:ok, nil} ->
            handle_cache_miss(query, cache_key, cache_config)

          {:ok, cached_result} ->
            cached_result

          _ ->
            execute(query)
        end
      end

      defp handle_cache_miss(query, cache_key, cache_config) do
        result = execute(query)

        if match?({:ok, _}, result) do
          ttl = Keyword.get(cache_config, :ttl, :timer.minutes(5))
          Cachex.put(:query_cache, cache_key, result, ttl: ttl)
        end

        result
      end

      defp generate_cache_key(query) do
        query
        |> Map.from_struct()
        |> :erlang.phash2()
        |> to_string()
      end

      defoverridable execute_with_cache: 1
    end
  end
end
