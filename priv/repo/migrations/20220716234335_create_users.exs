defmodule BaseAclEx.Repo.Migrations.CreateUsers do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:firstname, :string, size: 80, null: false)
      add(:lastname, :string, size: 80, null: false)
      add(:username, :string, size: 50, null: false)
      add(:email, :string, size: 255, null: false)
      add(:password_hash, :string, size: 118, null: false)

      add(:is_online, :boolean, default: false)
      add(:is_blocked, :boolean, default: false)
      add(:is_deleted, :boolean, default: false, null: false)

      timestamps()
      add(:deleted_at, :timestamp, default: nil)
    end

    create(unique_index(:users, :email))
    create(unique_index(:users, :username))
  end
end
