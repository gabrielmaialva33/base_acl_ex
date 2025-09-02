defmodule BaseAclEx.Repo.Migrations.CreateAuditLogsTable do
  use Ecto.Migration

  def change do
    create table(:audit_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :action, :string, null: false
      add :resource_type, :string, null: false
      add :resource_id, :binary_id
      add :permission_name, :string
      add :permission_check_result, :boolean
      add :ip_address, :inet
      add :user_agent, :text
      add :request_id, :uuid
      add :session_id, :string
      add :changes, :map, default: %{}
      add :metadata, :map, default: %{}
      add :error_message, :text
      add :duration_ms, :integer
      add :http_method, :string
      add :http_path, :string
      add :http_status, :integer
      add :context, :map, default: %{}
      
      inserted_at(:utc_datetime, null: false)
    end

    # No updated_at for audit logs (immutable)
    
    # Performance indexes
    create index(:audit_logs, [:user_id])
    create index(:audit_logs, [:action])
    create index(:audit_logs, [:resource_type])
    create index(:audit_logs, [:resource_type, :resource_id])
    create index(:audit_logs, [:permission_name])
    create index(:audit_logs, [:permission_check_result])
    create index(:audit_logs, [:inserted_at])
    create index(:audit_logs, [:ip_address])
    create index(:audit_logs, [:request_id])
    create index(:audit_logs, [:session_id])
    
    # Composite indexes for common queries
    create index(:audit_logs, [:user_id, :inserted_at])
    create index(:audit_logs, [:resource_type, :resource_id, :inserted_at])
    create index(:audit_logs, [:action, :inserted_at])
    create index(:audit_logs, [:permission_name, :permission_check_result, :inserted_at])
    create index(:audit_logs, [:user_id, :action, :inserted_at])
    
    # BRIN index for time-series data (very efficient for large tables)
    execute """
    CREATE INDEX audit_logs_inserted_at_brin_idx ON audit_logs 
    USING brin(inserted_at) WITH (pages_per_range = 128)
    """, "DROP INDEX audit_logs_inserted_at_brin_idx"
    
    # Partial indexes for common filters
    create index(:audit_logs, [:user_id, :permission_check_result], 
                where: "permission_check_result = false",
                name: :audit_logs_failed_permissions_idx)
    
    create index(:audit_logs, [:http_status], 
                where: "http_status >= 400",
                name: :audit_logs_error_status_idx)
    
    # Full-text search index
    execute """
    CREATE INDEX audit_logs_search_idx ON audit_logs 
    USING gin(to_tsvector('english', 
      coalesce(action, '') || ' ' || 
      coalesce(resource_type, '') || ' ' || 
      coalesce(permission_name, '') || ' ' || 
      coalesce(error_message, '')))
    """, "DROP INDEX audit_logs_search_idx"
  end
end