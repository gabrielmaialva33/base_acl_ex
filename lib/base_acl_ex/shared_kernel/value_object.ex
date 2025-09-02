defmodule BaseAclEx.SharedKernel.ValueObject do
  @moduledoc """
  Base module for value objects in the domain model.

  A value object is an immutable object that is defined by its attributes
  rather than a unique identity.
  """

  defmacro __using__(_opts) do
    quote do
      use Ecto.Schema
      import Ecto.Changeset

      @primary_key false
      @type t :: %__MODULE__{}

      # Value objects are equal if all their attributes are equal
      def equals?(%__MODULE__{} = vo1, %__MODULE__{} = vo2) do
        Map.from_struct(vo1) == Map.from_struct(vo2)
      end

      def equals?(_, _), do: false

      # Value objects should be immutable - create a new instance with changes
      def with_changes(%__MODULE__{} = vo, changes) when is_map(changes) do
        struct(vo, changes)
      end

      # Convert to primitive representation
      def to_primitive(%__MODULE__{} = vo) do
        vo
        |> Map.from_struct()
        |> Enum.reject(fn {_k, v} -> is_nil(v) end)
        |> Map.new()
      end

      defoverridable equals?: 2, with_changes: 2, to_primitive: 1
    end
  end

  @doc """
  Creates a new value object from primitive values.
  """
  def from_primitive(module, attrs) when is_map(attrs) do
    struct(module, attrs)
  end

  @doc """
  Validates that the value object is valid.
  """
  def validate(changeset) do
    changeset
  end
end
