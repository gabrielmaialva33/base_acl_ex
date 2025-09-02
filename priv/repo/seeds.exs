# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# Inside the script, you can read and write to any of your
# repositories directly:
#
#     BaseAclEx.Repo.insert!(%BaseAclEx.SomeSchema{})
#
# We recommend using the bang functions (`insert!`, `update!`
# and so on) as they will fail if something goes wrong.

alias BaseAclEx.Repo
alias BaseAclEx.Accounts.Core.Entities.User
alias BaseAclEx.Identity.Core.Entities.{Role, Permission, RolePermission, UserRole}

require Logger

defmodule BaseAclEx.Seeds do
  @moduledoc """
  Comprehensive seed data for BaseAclEx development and testing.
  This module provides idempotent seeding functions for roles, permissions, and users.
  """

  def run do
    Logger.info("🌱 Starting database seeding...")

    seed_permissions()
    seed_roles()
    seed_role_permissions()
    seed_users()
    seed_user_roles()

    Logger.info("✅ Database seeding completed successfully!")
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

    Enum.each(permissions, fn permission_attrs ->
      name = "#{permission_attrs.resource}.#{permission_attrs.action}.#{permission_attrs.context}"
      
      case Repo.get_by(Permission, name: name) do
        nil ->
          case Permission.new(permission_attrs) do
            %Ecto.Changeset{valid?: true} = changeset ->
              Repo.insert!(changeset)
              Logger.debug("  ✓ Created permission: #{name}")
            
            %Ecto.Changeset{valid?: false} = changeset ->
              Logger.error("  ✗ Failed to create permission #{name}: #{inspect(changeset.errors)}")
          end
        
        _existing ->
          Logger.debug("  → Permission already exists: #{name}")
      end
    end)

    Logger.info("📋 Permissions seeding completed")
  end

  defp seed_roles do
    Logger.info("👥 Seeding roles...")

    roles = [
      %{
        name: "Super Administrator",
        slug: "super-admin",
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

    Enum.each(roles, fn role_attrs ->
      case Repo.get_by(Role, slug: role_attrs.slug) do
        nil ->
          case Role.new(role_attrs) do
            %Ecto.Changeset{valid?: true} = changeset ->
              Repo.insert!(changeset)
              Logger.debug("  ✓ Created role: #{role_attrs.name}")
            
            %Ecto.Changeset{valid?: false} = changeset ->
              Logger.error("  ✗ Failed to create role #{role_attrs.name}: #{inspect(changeset.errors)}")
          end
        
        existing ->
          Logger.debug("  → Role already exists: #{existing.name}")
      end
    end)

    Logger.info("👥 Roles seeding completed")
  end

  defp seed_role_permissions do
    Logger.info("🔗 Seeding role-permission associations...")

    # Define permission sets for each role
    role_permissions = %{
      "super-admin" => [
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

    Enum.each(role_permissions, fn {role_slug, permission_names} ->
      role = Repo.get_by!(Role, slug: role_slug)
      
      Enum.each(permission_names, fn permission_name ->
        permission = Repo.get_by(Permission, name: permission_name)
        
        if permission do
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
              
              Logger.debug("  ✓ Granted #{permission_name} to #{role.name}")
            
            _existing ->
              Logger.debug("  → Permission #{permission_name} already granted to #{role.name}")
          end
        else
          Logger.warning("  ⚠ Permission not found: #{permission_name}")
        end
      end)
    end)

    Logger.info("🔗 Role-permission associations completed")
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
        phone_number: "+1234567890",
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
        phone_number: "+1234567891",
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
        phone_number: "+1234567892",
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
        phone_number: "+1234567894",
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

    Enum.each(users, fn user_attrs ->
      case Repo.get_by(User, email: user_attrs.email) do
        nil ->
          case User.new(user_attrs) do
            %Ecto.Changeset{valid?: true} = changeset ->
              Repo.insert!(changeset)
              Logger.debug("  ✓ Created user: #{user_attrs.email}")
            
            %Ecto.Changeset{valid?: false} = changeset ->
              Logger.error("  ✗ Failed to create user #{user_attrs.email}: #{inspect(changeset.errors)}")
          end
        
        existing ->
          Logger.debug("  → User already exists: #{existing.email}")
      end
    end)

    Logger.info("👤 Users seeding completed")
  end

  defp seed_user_roles do
    Logger.info("🎭 Seeding user-role assignments...")

    # Map users to their intended roles
    user_role_assignments = [
      {"superadmin@example.com", "super-admin"},
      {"admin@example.com", "admin"},
      {"moderator@example.com", "moderator"},
      {"john.doe@example.com", "user"},
      {"jane.smith@example.com", "user"},
      {"guest@example.com", "guest"}
    ]

    Enum.each(user_role_assignments, fn {email, role_slug} ->
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
          
          Logger.debug("  ✓ Assigned #{role.name} to #{user.email}")
        
        _existing ->
          Logger.debug("  → Role #{role.name} already assigned to #{user.email}")
      end
    end)

    Logger.info("🎭 User-role assignments completed")
  end
end

# Run the seeding
BaseAclEx.Seeds.run()