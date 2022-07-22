defmodule BaseAclEx.Accounts.Models.UserRole do
  use Ecto.Schema
  import Ecto.Changeset

  alias BaseAclEx.Accounts.Models.{Role, User, UserRole}

  # global fields
  @required_fields ~w(user_id role_id)a

  # user_role schema
  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @type t :: %UserRole{}
  schema "users_roles" do
    field :role_id, Ecto.UUID
    belongs_to :roles, Role, define_field: false

    field :user_id, Ecto.UUID
    belongs_to :users, User, define_field: false

    timestamps()
  end

  @doc false
  def changeset(user_role, attrs) do
    user_role
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
  end
end
