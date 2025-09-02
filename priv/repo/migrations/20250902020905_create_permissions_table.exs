defmodule BaseAclEx.Repo.Migrations.CreatePermissionsTable do
  use Ecto.Migration

  def change do
    create table(:permissions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :resource, :string, null: false
      add :action, :string, null: false
      add :context, :string, null: false, default: "any"
      add :description, :text
      add :category, :string
      add :is_active, :boolean, default: true, null: false
      add :is_system, :boolean, default: false, null: false
      add :requires_ownership, :boolean, default: false, null: false
      add :requires_two_factor, :boolean, default: false, null: false
      add :risk_level, :string, default: "low"
      add :metadata, :map, default: %{}
      add :conditions, :map, default: %{}
      add :dependencies, {:array, :string}, default: []

      timestamps(type: :utc_datetime)
    end

    # Unique constraint on permission combination
    create unique_index(:permissions, [:resource, :action, :context],
             name: :permissions_resource_action_context_unique
           )

    # Performance indexes
    create index(:permissions, [:name])
    create index(:permissions, [:resource])
    create index(:permissions, [:action])
    create index(:permissions, [:context])
    create index(:permissions, [:category])
    create index(:permissions, [:is_active])
    create index(:permissions, [:is_system])
    create index(:permissions, [:risk_level])

    # Composite indexes for common queries
    create index(:permissions, [:resource, :action])
    create index(:permissions, [:resource, :context])
    create index(:permissions, [:is_active, :resource])
    create index(:permissions, [:category, :is_active])

    # Full-text search index
    execute """
            CREATE INDEX permissions_search_idx ON permissions 
            USING gin(to_tsvector('english', 
              coalesce(name, '') || ' ' || 
              coalesce(resource, '') || ' ' || 
              coalesce(action, '') || ' ' || 
              coalesce(description, '')))
            """,
            "DROP INDEX permissions_search_idx"

    # Check constraint for risk level
    create constraint(:permissions, :valid_risk_level,
             check: "risk_level IN ('low', 'medium', 'high', 'critical')"
           )

    # Check constraint for context
    create constraint(:permissions, :valid_context,
             check: "context IN ('any', 'own', 'team', 'department', 'organization')"
           )
  end
end
