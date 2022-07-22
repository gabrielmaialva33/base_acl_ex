defmodule BaseAclEx.Repo.Migrations.CreateUsersRoles do
  use Ecto.Migration

  def change do
    create table(:users_roles, primary_key: false) do
      add(:id, :uuid, primary_key: true, null: false, default: fragment("uuid_generate_v4()"))

      add(:user_id, references(:users, type: :binary_id, column: :id, on_delete: :delete_all),
        null: false
      )

      add(:role_id, references(:roles, type: :binary_id, column: :id, on_delete: :delete_all),
        null: false
      )

      timestamps()
    end

    create(index(:users_roles, [:user_id]))
    create(index(:users_roles, [:role_id]))

    create(unique_index(:users_roles, [:user_id, :role_id], name: "users_roles_unique"))
  end
end
