defmodule BaseAclEx.Identity.Core.Entities.RolePermission do
  @moduledoc """
  Join table entity representing the many-to-many relationship between roles and permissions.
  Tracks which permissions are assigned to which roles.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "role_permissions" do
    belongs_to :role, BaseAclEx.Identity.Core.Entities.Role
    belongs_to :permission, BaseAclEx.Identity.Core.Entities.Permission

    field :granted_by, :binary_id
    field :revoked_at, :utc_datetime
    field :revoked_by, :binary_id
    field :metadata, :map, default: %{}

    timestamps(type: :utc_datetime)
  end

  @required_fields [:role_id, :permission_id]
  @optional_fields [:granted_by, :metadata]

  @doc """
  Creates a changeset for assigning a permission to a role.
  """
  def changeset(role_permission, attrs) do
    role_permission
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> foreign_key_constraint(:role_id)
    |> foreign_key_constraint(:permission_id)
    |> unique_constraint([:role_id, :permission_id],
      name: :role_permissions_role_id_permission_id_index,
      message: "Role already has this permission"
    )
  end

  @doc """
  Creates a changeset for revoking a permission from a role.
  """
  def revoke_changeset(role_permission, attrs) do
    role_permission
    |> cast(attrs, [:revoked_at, :revoked_by])
    |> validate_required([:revoked_at])
  end
end
