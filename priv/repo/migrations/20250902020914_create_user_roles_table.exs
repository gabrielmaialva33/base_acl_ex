defmodule BaseAclEx.Repo.Migrations.CreateUserRolesTable do
  use Ecto.Migration

  def change do
    create table(:user_roles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :role_id, references(:roles, type: :binary_id, on_delete: :delete_all), null: false
      add :granted_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :granted_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime
      add :is_active, :boolean, default: true, null: false
      add :scope, :string, default: "global"
      add :scope_id, :binary_id
      add :metadata, :map, default: %{}
      add :reason, :text

      timestamps(type: :utc_datetime)
    end

    # Unique constraint to prevent duplicate role assignments
    create unique_index(:user_roles, [:user_id, :role_id, :scope, :scope_id],
             where: "is_active = true",
             name: :user_roles_unique_active
           )

    # Performance indexes
    create index(:user_roles, [:user_id])
    create index(:user_roles, [:role_id])
    create index(:user_roles, [:granted_by_id])
    create index(:user_roles, [:expires_at], where: "expires_at IS NOT NULL")
    create index(:user_roles, [:is_active])
    create index(:user_roles, [:scope, :scope_id])

    # Composite indexes for common queries
    create index(:user_roles, [:user_id, :is_active])
    create index(:user_roles, [:role_id, :is_active])
    create index(:user_roles, [:user_id, :role_id, :is_active])
    create index(:user_roles, [:expires_at, :is_active], where: "expires_at IS NOT NULL")

    # Check constraint for scope
    create constraint(:user_roles, :valid_scope,
             check: "scope IN ('global', 'organization', 'department', 'team', 'project')"
           )
  end
end
