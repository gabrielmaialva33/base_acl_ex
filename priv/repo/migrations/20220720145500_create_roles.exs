defmodule BaseAclEx.Repo.Migrations.CreateRoles do
  use Ecto.Migration

  def change do
    create table(:roles, primary_key: false) do
      add(:id, :uuid, primary_key: true, null: false, default: fragment("uuid_generate_v4()"))

      add(:slug, :string, size: 20, null: false)
      add(:name, :string, size: 20, null: false)
      add(:description, :text, null: true)

      timestamps()
    end
  end
end
