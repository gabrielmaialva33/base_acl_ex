defmodule BaseAclEx.Accounts.Models.User do
  use Ecto.Schema
  import Ecto.Changeset

  @required_fields ~w(firstname lastname email username password)a
  @optional_fields ~w(is_online is_blocked is_deleted)a
  # @sortable_fields ~w(firstname lastname email username)a

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "users" do
    field :firstname, :string
    field :lastname, :string
    field :email, :string
    field :username, :string

    field :password, :string, virtual: true
    field :password_hash, :string

    field :is_online, :boolean, default: false
    field :is_blocked, :boolean, default: false
    field :is_deleted, :boolean, default: false

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
    |> validate_length(:firstname, min: 2, max: 80)
    |> validate_length(:lastname, min: 2, max: 80)
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
