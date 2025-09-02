defmodule BaseAclEx.Identity.Core.Entities.UserRole do
  @moduledoc """
  Join table entity representing the many-to-many relationship between users and roles.
  Tracks role assignments with metadata like who assigned it and when.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "user_roles" do
    belongs_to :user, BaseAclEx.Accounts.Core.Entities.User
    belongs_to :role, BaseAclEx.Identity.Core.Entities.Role

    field :granted_by_id, :binary_id
    field :granted_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :is_active, :boolean, default: true
    field :scope, :string, default: "global"
    field :scope_id, :binary_id
    field :reason, :string
    field :metadata, :map, default: %{}

    timestamps(type: :utc_datetime)
  end

  @required_fields [:user_id, :role_id]
  @optional_fields [
    :granted_by_id,
    :granted_at,
    :expires_at,
    :is_active,
    :scope,
    :scope_id,
    :reason,
    :metadata
  ]

  @doc """
  Creates a changeset for assigning a role to a user.
  """
  def changeset(user_role, attrs) do
    user_role
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:role_id)
    |> unique_constraint([:user_id, :role_id],
      name: :user_roles_user_id_role_id_index,
      message: "User already has this role"
    )
    |> validate_expiration()
  end

  @doc """
  Creates a changeset for revoking a role from a user.
  """
  def revoke_changeset(user_role, attrs) do
    user_role
    |> cast(attrs, [:is_active, :reason])
    |> put_change(:is_active, false)
  end

  defp validate_expiration(changeset) do
    case get_change(changeset, :expires_at) do
      nil ->
        changeset

      expires_at ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :lt do
          add_error(changeset, :expires_at, "must be in the future")
        else
          changeset
        end
    end
  end
end
