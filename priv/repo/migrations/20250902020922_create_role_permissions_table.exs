defmodule BaseAclEx.Repo.Migrations.CreateRolePermissionsTable do
  use Ecto.Migration

  def change do
    create table(:role_permissions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :role_id, references(:roles, type: :binary_id, on_delete: :delete_all), null: false

      add :permission_id, references(:permissions, type: :binary_id, on_delete: :delete_all),
        null: false

      add :granted_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :is_active, :boolean, default: true, null: false
      add :conditions, :map, default: %{}
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    # Unique constraint to prevent duplicate permission assignments
    create unique_index(:role_permissions, [:role_id, :permission_id],
             where: "is_active = true",
             name: :role_permissions_unique_active
           )

    # Performance indexes
    create index(:role_permissions, [:role_id])
    create index(:role_permissions, [:permission_id])
    create index(:role_permissions, [:is_active])
    create index(:role_permissions, [:granted_by_id])

    # Composite indexes for common queries
    create index(:role_permissions, [:role_id, :is_active])
    create index(:role_permissions, [:permission_id, :is_active])
    create index(:role_permissions, [:role_id, :permission_id, :is_active])
  end
end
