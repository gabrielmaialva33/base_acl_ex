defmodule BaseAclEx.Repo.Migrations.CreateUsersTable do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :email, :string, null: false
      add :username, :string
      add :password_hash, :string, null: false
      add :first_name, :string
      add :last_name, :string
      add :phone, :string
      add :avatar_url, :string
      add :is_active, :boolean, default: true, null: false
      add :is_deleted, :boolean, default: false, null: false
      add :deleted_at, :utc_datetime
      add :email_verified_at, :utc_datetime
      add :last_login_at, :utc_datetime
      add :failed_login_attempts, :integer, default: 0, null: false
      add :locked_until, :utc_datetime
      add :metadata, :map, default: %{}
      add :preferences, :map, default: %{}
      add :two_factor_enabled, :boolean, default: false, null: false
      add :two_factor_secret, :string

      timestamps(type: :utc_datetime)
    end

    # Unique indexes
    create unique_index(:users, [:email], where: "is_deleted = false", name: :users_email_unique_active)
    create unique_index(:users, [:username], where: "username IS NOT NULL AND is_deleted = false", name: :users_username_unique_active)
    
    # Performance indexes
    create index(:users, [:is_active, :is_deleted])
    create index(:users, [:email_verified_at])
    create index(:users, [:last_login_at])
    create index(:users, [:locked_until], where: "locked_until IS NOT NULL")
    
    # Full-text search index for user search
    execute """
    CREATE INDEX users_search_idx ON users 
    USING gin(to_tsvector('english', coalesce(email, '') || ' ' || 
                                     coalesce(username, '') || ' ' || 
                                     coalesce(first_name, '') || ' ' || 
                                     coalesce(last_name, '')))
    WHERE is_deleted = false
    """, "DROP INDEX users_search_idx"
  end
end