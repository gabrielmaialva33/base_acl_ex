defmodule BaseAclEx.Repo.Migrations.CreateRolesTable do
  use Ecto.Migration

  def change do
    create table(:roles, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :slug, :string, null: false
      add :description, :text
      add :is_active, :boolean, default: true, null: false
      add :is_system, :boolean, default: false, null: false
      add :hierarchy_level, :integer, null: false
      add :parent_role_id, references(:roles, type: :binary_id, on_delete: :nilify_all)
      add :metadata, :map, default: %{}
      add :color, :string
      add :icon, :string
      add :max_users, :integer
      add :features, {:array, :string}, default: []
      
      timestamps(type: :utc_datetime)
    end

    # Unique constraints
    create unique_index(:roles, [:slug], name: :roles_slug_unique)
    create unique_index(:roles, [:name], name: :roles_name_unique)
    
    # Performance indexes
    create index(:roles, [:is_active])
    create index(:roles, [:is_system])
    create index(:roles, [:hierarchy_level])
    create index(:roles, [:parent_role_id])
    
    # Composite indexes for common queries
    create index(:roles, [:is_active, :hierarchy_level])
    create index(:roles, [:parent_role_id, :hierarchy_level])
    
    # Check constraint for hierarchy level
    create constraint(:roles, :hierarchy_level_positive, check: "hierarchy_level >= 0")
  end
end