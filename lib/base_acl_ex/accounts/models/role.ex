defmodule BaseAclEx.Accounts.Models.Role do
  use Ecto.Schema
  import Ecto.Changeset

  alias BaseAclEx.Accounts.Models.{Role, User, UserRole}

  # global fields
  @required_fields ~w(slug name)a
  @optional_fields ~w(description)a

  # role schema
  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @type t :: %Role{}
  schema "roles" do
    field :slug, :string
    field :name, :string
    field :description, :string

    # set relationships
    many_to_many :users,
                 User,
                 join_through: UserRole,
                 join_keys: [
                   user_id: :id,
                   role_id: :id
                 ],
                 on_replace: :mark_as_invalid

    timestamps()
  end

  @doc false
  def changeset(role, attrs) do
    role
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
  end
end
