defmodule BaseAclEx.SharedKernel.AggregateRoot do
  @moduledoc """
  Base module for aggregate roots in the domain model.

  An aggregate root is the entry point to an aggregate, ensuring
  consistency and encapsulating business rules.
  """

  defmacro __using__(_opts) do
    quote do
      use Ecto.Schema
      import Ecto.Changeset

      @primary_key {:id, :binary_id, autogenerate: true}
      @foreign_key_type :binary_id
      @timestamps_opts [type: :utc_datetime]

      @type t :: %__MODULE__{}

      # Domain events that occurred during the aggregate's lifecycle
      @derive {Jason.Encoder, except: [:__meta__, :__struct__, :domain_events]}

      def apply_event(%__MODULE__{} = aggregate, event) do
        aggregate
        |> Map.update(:domain_events, [event], &[event | &1])
      end

      def clear_events(%__MODULE__{} = aggregate) do
        Map.put(aggregate, :domain_events, [])
      end

      def get_events(%__MODULE__{} = aggregate) do
        Map.get(aggregate, :domain_events, [])
      end

      defoverridable apply_event: 2, clear_events: 1, get_events: 1
    end
  end

  @doc """
  Validates that an aggregate has a valid ID.
  """
  def validate_id(changeset, field \\ :id) do
    import Ecto.Changeset

    changeset
    |> validate_required([field])
    |> validate_format(field, ~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      message: "must be a valid UUID"
    )
  end

  @doc """
  Adds optimistic locking version to the aggregate.
  """
  def with_optimistic_lock(schema) do
    schema
    |> Ecto.Schema.field(:version, :integer, default: 0)
  end

  @doc """
  Increments the version for optimistic locking.
  """
  def increment_version(changeset) do
    import Ecto.Changeset

    changeset
    |> update_change(:version, &(&1 + 1))
  end
end
