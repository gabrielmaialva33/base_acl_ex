defmodule Mix.Tasks.Seed do
  @shortdoc "Seeds the database with development data"

  @moduledoc """
  Mix task for seeding the database with comprehensive development data.

  ## Usage

      # Run full seeding (permissions, roles, users)
      mix seed

      # Run with specific components
      mix seed --only permissions
      mix seed --only roles
      mix seed --only users

      # Clear existing data before seeding (destructive!)
      mix seed --reset

  ## Examples

      # Seed everything
      mix seed

      # Only seed permissions and roles
      mix seed --only permissions,roles

      # Reset database and seed with fresh data
      mix seed --reset

  ## Safety

  This task is idempotent - it can be run multiple times safely.
  Existing records are not duplicated or modified.
  """

  use Mix.Task

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.Permission
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.Identity.Core.Entities.RolePermission
  alias BaseAclEx.Identity.Core.Entities.UserRole
  alias BaseAclEx.Repo

  require Logger

  @doc false
  def run(args) do
    Mix.Task.run("app.start")

    opts = parse_args(args)

    if opts[:reset] do
      Logger.warning("🗑️  Resetting database - this will delete ALL data!")
      Mix.shell().yes?("Are you sure you want to continue?") || Mix.raise("Aborted")
      reset_database()
    end

    components = opts[:only] || [:permissions, :roles, :role_permissions, :users, :user_roles]

    Logger.info("🌱 Starting database seeding with components: #{inspect(components)}")

    Enum.each(components, fn component ->
      case component do
        :permissions -> seed_permissions()
        :roles -> seed_roles()
        :role_permissions -> seed_role_permissions()
        :users -> seed_users()
        :user_roles -> seed_user_roles()
        _ -> Logger.warning("Unknown component: #{component}")
      end
    end)

    print_summary()
    Logger.info("✅ Database seeding completed successfully!")
  end

  defp parse_args(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [
          only: :string,
          reset: :boolean
        ],
        aliases: [
          o: :only,
          r: :reset
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

  defp reset_database do
    Logger.info("🗑️  Dropping and recreating database...")
    Mix.Task.run("ecto.reset", ["--no-start"])
  end

  defp seed_permissions do
    Logger.info("📋 Seeding permissions...")

    permissions = [
      # User Management Permissions
      %{
        resource: "users",
        action: "list",
        context: "any",
        description: "View list of all users",
        category: "identity",
        risk_level: "low"
      },
      %{
        resource: "users",
        action: "view",
        context: "any",
        description: "View any user profile",
        category: "identity",
        risk_level: "low"
      },
      %{
        resource: "users",
        action: "view",
        context: "own",
        description: "View own user profile",
        category: "identity",
        risk_level: "low",
        requires_ownership: true
      },
      %{
        resource: "users",
        action: "create",
        context: "any",
        description: "Create new users",
        category: "identity",
        risk_level: "medium"
      },
      %{
        resource: "users",
        action: "update",
        context: "any",
        description: "Update any user profile",
        category: "identity",
        risk_level: "medium"
      },
      %{
        resource: "users",
        action: "update",
        context: "own",
        description: "Update own user profile",
        category: "identity",
        risk_level: "low",
        requires_ownership: true
      },
      %{
        resource: "users",
        action: "delete",
        context: "any",
        description: "Delete any user",
        category: "identity",
        risk_level: "high"
      },
      %{
        resource: "users",
        action: "restore",
        context: "any",
        description: "Restore deleted users",
        category: "identity",
        risk_level: "medium"
      },
      %{
        resource: "users",
        action: "lock",
        context: "any",
        description: "Lock/unlock user accounts",
        category: "identity",
        risk_level: "medium"
      },
      %{
        resource: "users",
        action: "impersonate",
        context: "any",
        description: "Impersonate other users",
        category: "identity",
        risk_level: "critical",
        requires_two_factor: true
      },

      # Role Management Permissions
      %{
        resource: "roles",
        action: "list",
        context: "any",
        description: "View list of all roles",
        category: "identity",
        risk_level: "low"
      },
      %{
        resource: "roles",
        action: "view",
        context: "any",
        description: "View role details",
        category: "identity",
        risk_level: "low"
      },
      %{
        resource: "roles",
        action: "create",
        context: "any",
        description: "Create new roles",
        category: "identity",
        risk_level: "high"
      },
      %{
        resource: "roles",
        action: "update",
        context: "any",
        description: "Update role properties",
        category: "identity",
        risk_level: "high"
      },
      %{
        resource: "roles",
        action: "delete",
        context: "any",
        description: "Delete roles",
        category: "identity",
        risk_level: "critical"
      },
      %{
        resource: "roles",
        action: "assign",
        context: "any",
        description: "Assign roles to users",
        category: "identity",
        risk_level: "high"
      },
      %{
        resource: "roles",
        action: "revoke",
        context: "any",
        description: "Revoke roles from users",
        category: "identity",
        risk_level: "high"
      },

      # Permission Management Permissions
      %{
        resource: "permissions",
        action: "list",
        context: "any",
        description: "View list of all permissions",
        category: "identity",
        risk_level: "low"
      },
      %{
        resource: "permissions",
        action: "view",
        context: "any",
        description: "View permission details",
        category: "identity",
        risk_level: "low"
      },
      %{
        resource: "permissions",
        action: "create",
        context: "any",
        description: "Create new permissions",
        category: "identity",
        risk_level: "critical"
      },
      %{
        resource: "permissions",
        action: "update",
        context: "any",
        description: "Update permission properties",
        category: "identity",
        risk_level: "critical"
      },
      %{
        resource: "permissions",
        action: "delete",
        context: "any",
        description: "Delete permissions",
        category: "identity",
        risk_level: "critical"
      },
      %{
        resource: "permissions",
        action: "grant",
        context: "any",
        description: "Grant permissions to roles",
        category: "identity",
        risk_level: "critical"
      },
      %{
        resource: "permissions",
        action: "revoke",
        context: "any",
        description: "Revoke permissions from roles",
        category: "identity",
        risk_level: "critical"
      },

      # System Administration Permissions
      %{
        resource: "system",
        action: "admin",
        context: "any",
        description: "Full system administration access",
        category: "system",
        risk_level: "critical",
        requires_two_factor: true
      },
      %{
        resource: "system",
        action: "view_logs",
        context: "any",
        description: "View system audit logs",
        category: "system",
        risk_level: "medium"
      },
      %{
        resource: "system",
        action: "manage_settings",
        context: "any",
        description: "Manage system settings",
        category: "system",
        risk_level: "high"
      },
      %{
        resource: "system",
        action: "backup",
        context: "any",
        description: "Create system backups",
        category: "system",
        risk_level: "high"
      },
      %{
        resource: "system",
        action: "restore",
        context: "any",
        description: "Restore system from backup",
        category: "system",
        risk_level: "critical",
        requires_two_factor: true
      },

      # Audit Log Permissions
      %{
        resource: "audit_logs",
        action: "list",
        context: "any",
        description: "View audit log entries",
        category: "system",
        risk_level: "medium"
      },
      %{
        resource: "audit_logs",
        action: "view",
        context: "any",
        description: "View detailed audit log entry",
        category: "system",
        risk_level: "medium"
      },
      %{
        resource: "audit_logs",
        action: "export",
        context: "any",
        description: "Export audit logs",
        category: "system",
        risk_level: "high"
      },

      # Profile Management Permissions
      %{
        resource: "profile",
        action: "view",
        context: "own",
        description: "View own profile",
        category: "identity",
        risk_level: "low",
        requires_ownership: true
      },
      %{
        resource: "profile",
        action: "update",
        context: "own",
        description: "Update own profile",
        category: "identity",
        risk_level: "low",
        requires_ownership: true
      },
      %{
        resource: "profile",
        action: "change_password",
        context: "own",
        description: "Change own password",
        category: "identity",
        risk_level: "medium",
        requires_ownership: true
      },
      %{
        resource: "profile",
        action: "enable_2fa",
        context: "own",
        description: "Enable two-factor authentication",
        category: "identity",
        risk_level: "medium",
        requires_ownership: true
      },
      %{
        resource: "profile",
        action: "disable_2fa",
        context: "own",
        description: "Disable two-factor authentication",
        category: "identity",
        risk_level: "high",
        requires_ownership: true,
        requires_two_factor: true
      },

      # Content Management Permissions (example resources)
      %{
        resource: "posts",
        action: "list",
        context: "any",
        description: "View list of posts",
        category: "content",
        risk_level: "low"
      },
      %{
        resource: "posts",
        action: "view",
        context: "any",
        description: "View any post",
        category: "content",
        risk_level: "low"
      },
      %{
        resource: "posts",
        action: "view",
        context: "own",
        description: "View own posts",
        category: "content",
        risk_level: "low",
        requires_ownership: true
      },
      %{
        resource: "posts",
        action: "create",
        context: "any",
        description: "Create new posts",
        category: "content",
        risk_level: "low"
      },
      %{
        resource: "posts",
        action: "update",
        context: "any",
        description: "Update any post",
        category: "content",
        risk_level: "medium"
      },
      %{
        resource: "posts",
        action: "update",
        context: "own",
        description: "Update own posts",
        category: "content",
        risk_level: "low",
        requires_ownership: true
      },
      %{
        resource: "posts",
        action: "delete",
        context: "any",
        description: "Delete any post",
        category: "content",
        risk_level: "medium"
      },
      %{
        resource: "posts",
        action: "delete",
        context: "own",
        description: "Delete own posts",
        category: "content",
        risk_level: "low",
        requires_ownership: true
      },
      %{
        resource: "posts",
        action: "publish",
        context: "any",
        description: "Publish posts",
        category: "content",
        risk_level: "medium"
      },
      %{
        resource: "posts",
        action: "moderate",
        context: "any",
        description: "Moderate posts (approve/reject)",
        category: "content",
        risk_level: "medium"
      }
    ]

    count = length(permissions)
    Logger.info("  Creating #{count} permissions...")

    {created, existing} =
      Enum.reduce(permissions, {0, 0}, fn permission_attrs, {created_count, existing_count} ->
        name =
          "#{permission_attrs.resource}.#{permission_attrs.action}.#{permission_attrs.context}"

        case Repo.get_by(Permission, name: name) do
          nil ->
            case Permission.new(permission_attrs) do
              %Ecto.Changeset{valid?: true} = changeset ->
                Repo.insert!(changeset)
                Logger.debug("    ✓ Created permission: #{name}")
                {created_count + 1, existing_count}

              %Ecto.Changeset{valid?: false} = changeset ->
                Logger.error(
                  "    ✗ Failed to create permission #{name}: #{inspect(changeset.errors)}"
                )

                {created_count, existing_count}
            end

          _existing ->
            Logger.debug("    → Permission already exists: #{name}")
            {created_count, existing_count + 1}
        end
      end)

    Logger.info("📋 Permissions seeding completed: #{created} created, #{existing} existing")
  end

  defp seed_roles do
    Logger.info("👥 Seeding roles...")

    roles = [
      %{
        name: "Super Administrator",
        slug: "super_admin",
        description: "Full system access with all permissions",
        hierarchy_level: 100,
        is_system: true,
        is_active: true,
        color: "#dc2626",
        icon: "crown",
        features: ["system_admin", "user_impersonation", "audit_access", "backup_restore"],
        metadata: %{
          dangerous: true,
          requires_approval: true
        }
      },
      %{
        name: "Administrator",
        slug: "admin",
        description: "Administrative access to manage users and content",
        hierarchy_level: 90,
        is_system: true,
        is_active: true,
        color: "#dc2626",
        icon: "shield-check",
        features: ["user_management", "role_assignment", "content_moderation"],
        metadata: %{
          can_promote: false
        }
      },
      %{
        name: "Moderator",
        slug: "moderator",
        description: "Content moderation and user support",
        hierarchy_level: 70,
        is_system: true,
        is_active: true,
        color: "#f59e0b",
        icon: "shield",
        features: ["content_moderation", "user_support"],
        metadata: %{
          moderation_scope: "content"
        }
      },
      %{
        name: "User",
        slug: "user",
        description: "Standard user with basic access permissions",
        hierarchy_level: 30,
        is_system: true,
        is_active: true,
        color: "#10b981",
        icon: "user",
        features: ["profile_management", "content_creation"],
        metadata: %{
          default_role: true
        }
      },
      %{
        name: "Guest",
        slug: "guest",
        description: "Limited read-only access for unauthenticated users",
        hierarchy_level: 10,
        is_system: true,
        is_active: true,
        color: "#6b7280",
        icon: "user-circle",
        features: ["read_only"],
        metadata: %{
          public_role: true
        }
      }
    ]

    count = length(roles)
    Logger.info("  Creating #{count} roles...")

    {created, existing} =
      Enum.reduce(roles, {0, 0}, fn role_attrs, {created_count, existing_count} ->
        case Repo.get_by(Role, slug: role_attrs.slug) do
          nil ->
            case Role.new(role_attrs) do
              %Ecto.Changeset{valid?: true} = changeset ->
                Repo.insert!(changeset)
                Logger.debug("    ✓ Created role: #{role_attrs.name}")
                {created_count + 1, existing_count}

              %Ecto.Changeset{valid?: false} = changeset ->
                Logger.error(
                  "    ✗ Failed to create role #{role_attrs.name}: #{inspect(changeset.errors)}"
                )

                {created_count, existing_count}
            end

          existing ->
            Logger.debug("    → Role already exists: #{existing.name}")
            {created_count, existing_count + 1}
        end
      end)

    Logger.info("👥 Roles seeding completed: #{created} created, #{existing} existing")
  end

  defp seed_role_permissions do
    Logger.info("🔗 Seeding role-permission associations...")

    # Define permission sets for each role
    role_permissions = %{
      "super_admin" => [
        # Full system access - all permissions
        "system.admin.any",
        "system.view_logs.any",
        "system.manage_settings.any",
        "system.backup.any",
        "system.restore.any",
        "users.list.any",
        "users.view.any",
        "users.create.any",
        "users.update.any",
        "users.delete.any",
        "users.restore.any",
        "users.lock.any",
        "users.impersonate.any",
        "roles.list.any",
        "roles.view.any",
        "roles.create.any",
        "roles.update.any",
        "roles.delete.any",
        "roles.assign.any",
        "roles.revoke.any",
        "permissions.list.any",
        "permissions.view.any",
        "permissions.create.any",
        "permissions.update.any",
        "permissions.delete.any",
        "permissions.grant.any",
        "permissions.revoke.any",
        "audit_logs.list.any",
        "audit_logs.view.any",
        "audit_logs.export.any",
        "posts.list.any",
        "posts.view.any",
        "posts.create.any",
        "posts.update.any",
        "posts.delete.any",
        "posts.publish.any",
        "posts.moderate.any"
      ],
      "admin" => [
        # Administrative access without system-level controls
        "users.list.any",
        "users.view.any",
        "users.create.any",
        "users.update.any",
        "users.lock.any",
        "roles.list.any",
        "roles.view.any",
        "roles.assign.any",
        "roles.revoke.any",
        "permissions.list.any",
        "permissions.view.any",
        "audit_logs.list.any",
        "audit_logs.view.any",
        "posts.list.any",
        "posts.view.any",
        "posts.create.any",
        "posts.update.any",
        "posts.delete.any",
        "posts.publish.any",
        "posts.moderate.any"
      ],
      "moderator" => [
        # Content moderation and limited user management
        "users.list.any",
        "users.view.any",
        "users.lock.any",
        "roles.list.any",
        "roles.view.any",
        "posts.list.any",
        "posts.view.any",
        "posts.update.any",
        "posts.delete.any",
        "posts.moderate.any",
        "profile.view.own",
        "profile.update.own",
        "profile.change_password.own"
      ],
      "user" => [
        # Basic user permissions + own content management
        "users.view.own",
        "posts.list.any",
        "posts.view.any",
        "posts.create.any",
        "posts.view.own",
        "posts.update.own",
        "posts.delete.own",
        "profile.view.own",
        "profile.update.own",
        "profile.change_password.own",
        "profile.enable_2fa.own",
        "profile.disable_2fa.own"
      ],
      "guest" => [
        # Read-only access
        "posts.list.any",
        "posts.view.any"
      ]
    }

    total_associations = Enum.sum(Enum.map(role_permissions, fn {_, perms} -> length(perms) end))
    Logger.info("  Creating #{total_associations} role-permission associations...")

    {created, existing, missing} =
      Enum.reduce(role_permissions, {0, 0, 0}, fn {role_slug, permission_names}, acc ->
        role = Repo.get_by!(Role, slug: role_slug)
        grant_permissions_to_role_with_counts(role, permission_names, acc)
      end)

    Logger.info(
      "🔗 Role-permission associations completed: #{created} created, #{existing} existing, #{missing} missing"
    )
  end

  defp grant_permissions_to_role_with_counts(
         role,
         permission_names,
         {created_count, existing_count, missing_count}
       ) do
    Enum.reduce(
      permission_names,
      {created_count, existing_count, missing_count},
      fn permission_name, counts ->
        permission = Repo.get_by(Permission, name: permission_name)
        process_permission_grant(role, permission, permission_name, counts)
      end
    )
  end

  defp process_permission_grant(_role, nil, permission_name, {cc, ec, mc}) do
    Logger.warning("    ⚠ Permission not found: #{permission_name}")
    {cc, ec, mc + 1}
  end

  defp process_permission_grant(role, permission, permission_name, {cc, ec, mc}) do
    case Repo.get_by(RolePermission, role_id: role.id, permission_id: permission.id) do
      nil ->
        %RolePermission{}
        |> RolePermission.changeset(%{
          role_id: role.id,
          permission_id: permission.id,
          is_active: true,
          metadata: %{seeded: true}
        })
        |> Repo.insert!()

        Logger.debug("    ✓ Granted #{permission_name} to #{role.name}")
        {cc + 1, ec, mc}

      _existing ->
        Logger.debug("    → Permission #{permission_name} already granted to #{role.name}")

        {cc, ec + 1, mc}
    end
  end

  defp seed_users do
    Logger.info("👤 Seeding sample users...")

    users = [
      %{
        email: "superadmin@example.com",
        username: "superadmin",
        password: "SuperAdmin123!",
        first_name: "Super",
        last_name: "Administrator",
        phone: "+1234567890",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          role: "super-admin"
        }
      },
      %{
        email: "admin@example.com",
        username: "admin",
        password: "Admin123!",
        first_name: "System",
        last_name: "Administrator",
        phone: "+1234567891",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          role: "admin"
        }
      },
      %{
        email: "moderator@example.com",
        username: "moderator",
        password: "Moderator123!",
        first_name: "Content",
        last_name: "Moderator",
        phone: "+1234567892",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          role: "moderator"
        }
      },
      %{
        email: "john.doe@example.com",
        username: "johndoe",
        password: "JohnDoe123!",
        first_name: "John",
        last_name: "Doe",
        phone: "+1234567893",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          role: "user"
        }
      },
      %{
        email: "jane.smith@example.com",
        username: "janesmith",
        password: "JaneSmith123!",
        first_name: "Jane",
        last_name: "Smith",
        phone: "+1234567894",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          role: "user"
        }
      },
      %{
        email: "guest@example.com",
        username: "guest",
        password: "Guest123!",
        first_name: "Guest",
        last_name: "User",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          role: "guest"
        }
      }
    ]

    count = length(users)
    Logger.info("  Creating #{count} users...")

    {created, existing} =
      Enum.reduce(users, {0, 0}, fn user_attrs, {created_count, existing_count} ->
        case Repo.get_by(User, email: user_attrs.email) do
          nil ->
            case User.new(user_attrs) do
              %Ecto.Changeset{valid?: true} = changeset ->
                Repo.insert!(changeset)
                Logger.debug("    ✓ Created user: #{user_attrs.email}")
                {created_count + 1, existing_count}

              %Ecto.Changeset{valid?: false} = changeset ->
                Logger.error(
                  "    ✗ Failed to create user #{user_attrs.email}: #{inspect(changeset.errors)}"
                )

                {created_count, existing_count}
            end

          existing ->
            Logger.debug("    → User already exists: #{existing.email}")
            {created_count, existing_count + 1}
        end
      end)

    Logger.info("👤 Users seeding completed: #{created} created, #{existing} existing")
  end

  defp seed_user_roles do
    Logger.info("🎭 Seeding user-role assignments...")

    # Map users to their intended roles
    user_role_assignments = [
      {"superadmin@example.com", "super_admin"},
      {"admin@example.com", "admin"},
      {"moderator@example.com", "moderator"},
      {"john.doe@example.com", "user"},
      {"jane.smith@example.com", "user"},
      {"guest@example.com", "guest"}
    ]

    count = length(user_role_assignments)
    Logger.info("  Creating #{count} user-role assignments...")

    {created, existing} =
      Enum.reduce(user_role_assignments, {0, 0}, fn {email, role_slug},
                                                    {created_count, existing_count} ->
        user = Repo.get_by!(User, email: email)
        role = Repo.get_by!(Role, slug: role_slug)

        case Repo.get_by(UserRole, user_id: user.id, role_id: role.id) do
          nil ->
            %UserRole{}
            |> UserRole.changeset(%{
              user_id: user.id,
              role_id: role.id,
              granted_at: DateTime.utc_now(),
              is_active: true,
              scope: "global",
              reason: "Initial seeding - default role assignment",
              metadata: %{seeded: true}
            })
            |> Repo.insert!()

            Logger.debug("    ✓ Assigned #{role.name} to #{user.email}")
            {created_count + 1, existing_count}

          _existing ->
            Logger.debug("    → Role #{role.name} already assigned to #{user.email}")
            {created_count, existing_count + 1}
        end
      end)

    Logger.info("🎭 User-role assignments completed: #{created} created, #{existing} existing")
  end

  defp print_summary do
    Logger.info("\n📊 Database Summary:")

    permission_count = Repo.aggregate(Permission, :count, :id)
    role_count = Repo.aggregate(Role, :count, :id)
    user_count = Repo.aggregate(User, :count, :id)
    role_permission_count = Repo.aggregate(RolePermission, :count, :id)
    user_role_count = Repo.aggregate(UserRole, :count, :id)

    Logger.info("  📋 Permissions: #{permission_count}")
    Logger.info("  👥 Roles: #{role_count}")
    Logger.info("  👤 Users: #{user_count}")
    Logger.info("  🔗 Role-Permission associations: #{role_permission_count}")
    Logger.info("  🎭 User-Role assignments: #{user_role_count}")

    Logger.info("\n🔐 Sample Login Credentials:")
    Logger.info("  Super Admin: superadmin@example.com / SuperAdmin123!")
    Logger.info("  Admin:       admin@example.com / Admin123!")
    Logger.info("  Moderator:   moderator@example.com / Moderator123!")
    Logger.info("  User:        john.doe@example.com / JohnDoe123!")
    Logger.info("  Guest:       guest@example.com / Guest123!")
  end
end
