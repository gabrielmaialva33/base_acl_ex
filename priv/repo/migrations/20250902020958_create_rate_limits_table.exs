defmodule BaseAclEx.Repo.Migrations.CreateRateLimitsTable do
  use Ecto.Migration

  def change do
    create table(:rate_limits, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :key, :string, null: false
      add :bucket_type, :string, null: false, default: "user"
      add :bucket_id, :string, null: false
      add :action, :string, null: false
      add :limit_value, :integer, null: false
      add :window_seconds, :integer, null: false
      add :current_count, :integer, default: 0, null: false
      add :window_start, :utc_datetime, null: false
      add :window_end, :utc_datetime, null: false
      add :last_request_at, :utc_datetime
      add :blocked_until, :utc_datetime
      add :total_requests, :bigint, default: 0, null: false
      add :total_blocked, :bigint, default: 0, null: false
      add :metadata, :map, default: %{}
      
      timestamps(type: :utc_datetime)
    end

    # Unique constraint for rate limit key
    create unique_index(:rate_limits, [:key, :bucket_type, :bucket_id, :action], 
                       name: :rate_limits_unique_key)
    
    # Performance indexes
    create index(:rate_limits, [:bucket_type])
    create index(:rate_limits, [:bucket_id])
    create index(:rate_limits, [:action])
    create index(:rate_limits, [:window_end])
    create index(:rate_limits, [:blocked_until], where: "blocked_until IS NOT NULL")
    
    # Composite indexes for common queries
    create index(:rate_limits, [:bucket_type, :bucket_id])
    create index(:rate_limits, [:bucket_type, :bucket_id, :action])
    create index(:rate_limits, [:window_end, :current_count])
    
    # Partial index for blocks (without NOW() which is not immutable)
    create index(:rate_limits, [:bucket_id, :blocked_until], 
                where: "blocked_until IS NOT NULL",
                name: :rate_limits_active_blocks_idx)
    
    # Check constraint for bucket type
    create constraint(:rate_limits, :valid_bucket_type, 
                     check: "bucket_type IN ('user', 'ip', 'api_key', 'global', 'endpoint')")
    
    # Check constraint for positive values
    create constraint(:rate_limits, :positive_limit, check: "limit_value > 0")
    create constraint(:rate_limits, :positive_window, check: "window_seconds > 0")
    create constraint(:rate_limits, :non_negative_count, check: "current_count >= 0")
  end
end