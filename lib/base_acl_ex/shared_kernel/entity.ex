defmodule BaseAclEx.SharedKernel.Entity do
  @moduledoc """
  Base module for entities in the domain model.

  An entity is an object with a unique identity that persists over time.
  """

  defmacro __using__(_opts) do
    quote do
      use Ecto.Schema
      import Ecto.Changeset

      @primary_key {:id, :binary_id, autogenerate: true}
      @foreign_key_type :binary_id
      @timestamps_opts [type: :utc_datetime]

      @type t :: %__MODULE__{}

      # We need to define these functions after the schema is defined
      # Using @before_compile to ensure the struct is available
      @before_compile BaseAclEx.SharedKernel.Entity
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      # Default equality based on ID
      def equals?(%{__struct__: __MODULE__, id: id1}, %{__struct__: __MODULE__, id: id2})
          when is_binary(id1) and is_binary(id2) do
        id1 == id2
      end

      def equals?(_, _), do: false

      # Check if entity is persisted
      def persisted?(%{__struct__: __MODULE__, id: nil}), do: false
      def persisted?(%{__struct__: __MODULE__, id: _}), do: true

      # Get entity identity
      def identity(%{__struct__: __MODULE__, id: id}), do: id

      defoverridable equals?: 2, persisted?: 1, identity: 1
    end
  end

  @doc """
  Base validation for entities.
  """
  def validate_entity(changeset) do
    import Ecto.Changeset

    changeset
    |> validate_required([:id])
  end
end
