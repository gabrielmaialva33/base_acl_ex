defmodule BaseAclEx.Accounts.Models.User do
  use Ecto.Schema
  import Ecto.Changeset

  @required_fields [:first_name, :last_name, :email, :password]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "users" do

    field :firstname, :string
    field :lastname, :string
    field :email, :string
    field :username, :string
    field :password_hash, :string

    field :is_deleted, :boolean, default: false

    timestamps()
  end

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, [:firstname, :lastname, :username, :email, :password_hash, :is_deleted])
    |> validate_required(@required_fields)
  end
end
