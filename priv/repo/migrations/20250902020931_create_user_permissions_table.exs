defmodule BaseAclEx.Repo.Migrations.CreateUserPermissionsTable do
  use Ecto.Migration

  def change do
    create table(:user_permissions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :permission_id, references(:permissions, type: :binary_id, on_delete: :delete_all), null: false
      add :granted_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :granted_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime
      add :revoked_at, :utc_datetime
      add :revoked_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :is_granted, :boolean, default: true, null: false
      add :is_active, :boolean, default: true, null: false
      add :scope, :string, default: "global"
      add :scope_id, :binary_id
      add :conditions, :map, default: %{}
      add :metadata, :map, default: %{}
      add :reason, :text
      add :priority, :integer, default: 0
      
      timestamps(type: :utc_datetime)
    end

    # Unique constraint to prevent duplicate permission assignments
    create unique_index(:user_permissions, [:user_id, :permission_id, :scope, :scope_id], 
                       where: "is_active = true",
                       name: :user_permissions_unique_active)
    
    # Performance indexes
    create index(:user_permissions, [:user_id])
    create index(:user_permissions, [:permission_id])
    create index(:user_permissions, [:granted_by_id])
    create index(:user_permissions, [:revoked_by_id])
    create index(:user_permissions, [:expires_at], where: "expires_at IS NOT NULL")
    create index(:user_permissions, [:revoked_at], where: "revoked_at IS NOT NULL")
    create index(:user_permissions, [:is_granted])
    create index(:user_permissions, [:is_active])
    create index(:user_permissions, [:scope, :scope_id])
    create index(:user_permissions, [:priority])
    
    # Composite indexes for common queries
    create index(:user_permissions, [:user_id, :is_active, :is_granted])
    create index(:user_permissions, [:permission_id, :is_active])
    create index(:user_permissions, [:user_id, :permission_id, :is_active])
    create index(:user_permissions, [:expires_at, :is_active], where: "expires_at IS NOT NULL")
    create index(:user_permissions, [:user_id, :is_active, :priority])
    
    # Check constraint for scope
    create constraint(:user_permissions, :valid_scope, 
                     check: "scope IN ('global', 'organization', 'department', 'team', 'project')")
  end
end