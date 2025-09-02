defmodule BaseAclEx.Repo.Migrations.CreateAccessTokensTable do
  use Ecto.Migration

  def change do
    create table(:access_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :token_hash, :string, null: false
      add :jti, :string, null: false
      add :token_type, :string, null: false, default: "access"
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime
      add :revoked_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :revoke_reason, :text
      add :last_used_at, :utc_datetime
      add :used_count, :integer, default: 0, null: false
      add :ip_address, :inet
      add :user_agent, :text
      add :device_id, :string
      add :device_name, :string
      add :scopes, {:array, :string}, default: []
      add :metadata, :map, default: %{}
      add :refresh_token_id, references(:access_tokens, type: :binary_id, on_delete: :delete_all)
      
      timestamps(type: :utc_datetime)
    end

    # Unique indexes
    create unique_index(:access_tokens, [:token_hash], name: :access_tokens_token_hash_unique)
    create unique_index(:access_tokens, [:jti], name: :access_tokens_jti_unique)
    
    # Performance indexes
    create index(:access_tokens, [:user_id])
    create index(:access_tokens, [:token_type])
    create index(:access_tokens, [:expires_at])
    create index(:access_tokens, [:revoked_at], where: "revoked_at IS NOT NULL")
    create index(:access_tokens, [:last_used_at])
    create index(:access_tokens, [:device_id])
    create index(:access_tokens, [:refresh_token_id])
    
    # Composite indexes for common queries
    create index(:access_tokens, [:user_id, :token_type, :revoked_at])
    create index(:access_tokens, [:user_id, :expires_at], where: "revoked_at IS NULL")
    create index(:access_tokens, [:token_type, :expires_at], where: "revoked_at IS NULL")
    create index(:access_tokens, [:user_id, :device_id], where: "revoked_at IS NULL")
    
    # Partial index for active tokens
    create index(:access_tokens, [:user_id, :token_type], 
                where: "revoked_at IS NULL AND expires_at > NOW()",
                name: :access_tokens_active_idx)
    
    # Check constraint for token type
    create constraint(:access_tokens, :valid_token_type, 
                     check: "token_type IN ('access', 'refresh', 'api', 'personal', 'service')")
  end
end