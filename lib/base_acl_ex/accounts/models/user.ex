defmodule BaseAclEx.Accounts.Models.User do
  use Ecto.Schema
  import Ecto.Changeset

  alias BaseAclEx.Accounts.Models.{Role, User, UserRole}

  # global fields
  @required_fields ~w(first_name last_name email username password)a
  @optional_fields ~w(is_online is_blocked is_deleted)a
  @sortable_fields ~w(first_name last_name email username)a

  # flop config schema
  @derive {
    Flop.Schema,
    filterable: @sortable_fields ++ [:search],
    sortable: @sortable_fields ++ [:search],
    default_limit: 10,
    max_limit: 100,
    default_order: %{
      order_by: @sortable_fields,
      order_directions: [:asc]
    },
    compound_fields: [search: @sortable_fields]
  }

  # user schema
  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @type t :: %User{}
  schema "users" do
    field :first_name, :string
    field :last_name, :string
    field :email, :string
    field :username, :string

    field :password, :string, virtual: true
    field :password_hash, :string

    field :is_online, :boolean, default: false
    field :is_blocked, :boolean, default: false
    field :is_deleted, :boolean, default: false

    # set relationships
    many_to_many :roles,
                 Role,
                 join_through: UserRole,
                 join_keys: [
                   user_id: :id,
                   role_id: :id
                 ],
                 on_replace: :mark_as_invalid

    timestamps()
  end

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_changeset
  end

  defp validate_changeset(user) do
    user
    |> validate_length(:first_name, min: 2, max: 80)
    |> validate_length(:last_name, min: 2, max: 80)
    |> validate_length(:username, min: 2, max: 50)
    |> validate_format(:email, ~r/@/)
    |> validate_length(:password, min: 6)
    |> validate_format(
      :password,
      ~r/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).*/,
      message: "Must include at least one lowercase letter, one uppercase letter, and one digit"
    )
    |> unique_constraint(:email)
    |> unique_constraint(:username)
    |> generate_password_hash
  end

  defp generate_password_hash(changeset) do
    case changeset do
      %Ecto.Changeset{
        valid?: true,
        changes: %{
          password: password
        }
      } ->
        put_change(changeset, :password_hash, Argon2.hash_pwd_salt(password, salt_len: 32))

      _ ->
        changeset
    end
  end
end
