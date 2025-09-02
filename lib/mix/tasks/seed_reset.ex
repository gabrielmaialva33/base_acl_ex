defmodule Mix.Tasks.SeedReset do
  @shortdoc "Resets seeded data and re-seeds the database"

  @moduledoc """
  Mix task for clearing existing seed data and reseeding with fresh data.

  This task provides a safe way to reset only the seeded development data
  without affecting user-created data in production environments.

  ## Usage

      # Clear all seed data and reseed
      mix seed_reset

      # Clear and reseed specific components
      mix seed_reset --only users
      mix seed_reset --only permissions,roles

      # Force reset without confirmation (use with caution!)
      mix seed_reset --force

  ## What gets reset

  This task only removes data that was created by the seeding process:
  - Users with metadata.seeded = true
  - Roles that are system roles (is_system = true)
  - Permissions created by seeding
  - Role-permission associations with metadata.seeded = true
  - User-role assignments with metadata.seeded = true

  ## Safety

  - Always asks for confirmation unless --force is used
  - Only removes data created by seeding (identified by metadata)
  - Preserves user-created production data
  - Cannot be undone - use with caution!
  """

  use Mix.Task

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.Permission
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.Identity.Core.Entities.RolePermission
  alias BaseAclEx.Identity.Core.Entities.UserRole
  alias BaseAclEx.Repo

  import Ecto.Query
  require Logger

  @doc false
  def run(args) do
    Mix.Task.run("app.start")

    opts = parse_args(args)
    confirm_reset_unless_forced(opts)
    clear_components(opts)
    reseed_data()

    Logger.info("✅ Seed reset completed successfully!")
  end

  defp confirm_reset_unless_forced(opts) do
    unless opts[:force] do
      Logger.warning("🚨 This will delete seeded data from the database!")
      Mix.shell().yes?("Are you sure you want to continue?") || Mix.raise("Aborted")
    end
  end

  defp clear_components(opts) do
    components = opts[:only] || [:user_roles, :role_permissions, :users, :roles, :permissions]
    Logger.info("🗑️  Starting seed data reset for components: #{inspect(components)}")

    # Delete in reverse dependency order
    Enum.each(components, &clear_component/1)
  end

  defp clear_component(:user_roles), do: clear_user_roles()
  defp clear_component(:role_permissions), do: clear_role_permissions()
  defp clear_component(:users), do: clear_seeded_users()
  defp clear_component(:roles), do: clear_system_roles()
  defp clear_component(:permissions), do: clear_seeded_permissions()
  defp clear_component(unknown), do: Logger.warning("Unknown component: #{unknown}")

  defp reseed_data do
    Logger.info("🌱 Reseeding with fresh data...")
    Mix.Task.run("seed", [])
  end

  defp parse_args(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [
          only: :string,
          force: :boolean
        ],
        aliases: [
          o: :only,
          f: :force
        ]
      )

    # Parse comma-separated components
    components =
      case opts[:only] do
        nil -> nil
        string -> string |> String.split(",") |> Enum.map(&String.to_atom(String.trim(&1)))
      end

    opts
    |> Keyword.put(:only, components)
  end

  defp clear_user_roles do
    Logger.info("🎭 Clearing seeded user-role assignments...")

    query = from(ur in UserRole, where: fragment("?->>'seeded' = 'true'", ur.metadata))
    {count, _} = Repo.delete_all(query)

    Logger.info("  Deleted #{count} seeded user-role assignments")
  end

  defp clear_role_permissions do
    Logger.info("🔗 Clearing seeded role-permission associations...")

    query = from(rp in RolePermission, where: fragment("?->>'seeded' = 'true'", rp.metadata))
    {count, _} = Repo.delete_all(query)

    Logger.info("  Deleted #{count} seeded role-permission associations")
  end

  defp clear_seeded_users do
    Logger.info("👤 Clearing seeded users...")

    query = from(u in User, where: fragment("?->>'seeded' = 'true'", u.metadata))
    {count, _} = Repo.delete_all(query)

    Logger.info("  Deleted #{count} seeded users")
  end

  defp clear_system_roles do
    Logger.info("👥 Clearing system roles...")

    # Only delete system roles that are not referenced by any non-seeded user roles
    subquery =
      from(ur in UserRole,
        where: not fragment("?->>'seeded' = 'true'", ur.metadata),
        select: ur.role_id
      )

    query =
      from(r in Role,
        where: r.is_system == true,
        where: r.id not in subquery(subquery)
      )

    {count, _} = Repo.delete_all(query)

    Logger.info("  Deleted #{count} system roles")
  end

  defp clear_seeded_permissions do
    Logger.info("📋 Clearing seeded permissions...")

    # Get permission IDs that are only used in seeded role-permissions
    non_seeded_role_permissions =
      from(rp in RolePermission,
        where: not fragment("?->>'seeded' = 'true'", rp.metadata),
        select: rp.permission_id
      )

    seeded_permission_ids =
      from(p in Permission,
        where: p.id not in subquery(non_seeded_role_permissions),
        select: p.id
      )
      |> Repo.all()

    if length(seeded_permission_ids) > 0 do
      query = from(p in Permission, where: p.id in ^seeded_permission_ids)
      {count, _} = Repo.delete_all(query)
      Logger.info("  Deleted #{count} seeded permissions")
    else
      Logger.info("  No seeded permissions to delete")
    end
  end
end
