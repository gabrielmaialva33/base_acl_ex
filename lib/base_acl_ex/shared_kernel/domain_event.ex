defmodule BaseAclEx.SharedKernel.DomainEvent do
  @moduledoc """
  Base behaviour for domain events.
  
  Domain events represent something that happened in the domain that
  other parts of the system might be interested in.
  """

  @type t :: %{
          __struct__: atom(),
          aggregate_id: String.t(),
          occurred_at: DateTime.t(),
          metadata: map()
        }

  @callback aggregate_id() :: String.t()
  @callback occurred_at() :: DateTime.t()
  @callback event_type() :: atom()
  @callback event_version() :: String.t()
  @callback payload() :: map()

  defmacro __using__(_opts) do
    quote do
      @behaviour BaseAclEx.SharedKernel.DomainEvent

      @derive Jason.Encoder
      defstruct [
        :aggregate_id,
        :occurred_at,
        :metadata,
        :payload,
        event_type: __MODULE__ |> Module.split() |> List.last() |> Macro.underscore() |> String.to_atom(),
        event_version: "1.0.0"
      ]

      @impl true
      def aggregate_id, do: raise("aggregate_id/0 not implemented")

      @impl true
      def occurred_at, do: DateTime.utc_now()

      @impl true
      def event_type, do: __MODULE__ |> Module.split() |> List.last() |> Macro.underscore() |> String.to_atom()

      @impl true
      def event_version, do: "1.0.0"

      @impl true
      def payload, do: %{}

      defoverridable aggregate_id: 0, occurred_at: 0, event_type: 0, event_version: 0, payload: 0
    end
  end

  @doc """
  Creates a new domain event with the given aggregate_id and payload.
  """
  def new(module, aggregate_id, payload \\ %{}, metadata \\ %{}) do
    struct!(module, %{
      aggregate_id: aggregate_id,
      occurred_at: DateTime.utc_now(),
      payload: payload,
      metadata: enrich_metadata(metadata)
    })
  end

  defp enrich_metadata(metadata) do
    Map.merge(
      %{
        correlation_id: metadata[:correlation_id] || Ecto.UUID.generate(),
        causation_id: metadata[:causation_id] || Ecto.UUID.generate(),
        user_id: metadata[:user_id],
        ip_address: metadata[:ip_address],
        user_agent: metadata[:user_agent]
      },
      metadata
    )
  end
end