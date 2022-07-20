defmodule BaseAclEx.Accounts.Models.Role do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "roles" do
    field :slug, :string
    field :name, :string
    field :description, :string

    timestamps()
  end

  @doc false
  def changeset(role, attrs) do
    role
    |> cast(attrs, [:slug, :name, :description])
    |> validate_required([:slug, :name, :description])
  end
end
