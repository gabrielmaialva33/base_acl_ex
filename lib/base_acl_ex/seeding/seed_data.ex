defmodule BaseAclEx.Seeding.SeedData do
  @moduledoc """
  Shared seed data definitions for consistent seeding across different environments.
  """

  @doc "Returns the permission definitions for seeding"
  def permission_definitions do
    [
      # User management permissions
      %{
        name: "users.create.any",
        description: "Create any user account",
        scope: "any",
        resource: "users",
        action: "create",
        is_active: true,
        metadata: %{
          category: "user_management",
          risk_level: "high",
          requires_2fa: true,
          seeded: true
        }
      },
      %{
        name: "users.read.any",
        description: "View any user information",
        scope: "any",
        resource: "users",
        action: "read",
        is_active: true,
        metadata: %{
          category: "user_management",
          risk_level: "medium",
          seeded: true
        }
      },
      %{
        name: "users.read.own",
        description: "View own user information",
        scope: "own",
        resource: "users",
        action: "read",
        is_active: true,
        metadata: %{
          category: "user_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "users.update.any",
        description: "Update any user information",
        scope: "any",
        resource: "users",
        action: "update",
        is_active: true,
        metadata: %{
          category: "user_management",
          risk_level: "high",
          requires_2fa: true,
          seeded: true
        }
      },
      %{
        name: "users.update.own",
        description: "Update own user information",
        scope: "own",
        resource: "users",
        action: "update",
        is_active: true,
        metadata: %{
          category: "user_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "users.delete.any",
        description: "Delete any user account",
        scope: "any",
        resource: "users",
        action: "delete",
        is_active: true,
        metadata: %{
          category: "user_management",
          risk_level: "critical",
          requires_2fa: true,
          requires_approval: true,
          seeded: true
        }
      },
      %{
        name: "users.delete.own",
        description: "Delete own user account",
        scope: "own",
        resource: "users",
        action: "delete",
        is_active: true,
        metadata: %{
          category: "user_management",
          risk_level: "medium",
          requires_confirmation: true,
          seeded: true
        }
      },

      # Role management permissions
      %{
        name: "roles.create.any",
        description: "Create new roles",
        scope: "any",
        resource: "roles",
        action: "create",
        is_active: true,
        metadata: %{
          category: "role_management",
          risk_level: "critical",
          requires_2fa: true,
          audit_required: true,
          seeded: true
        }
      },
      %{
        name: "roles.read.any",
        description: "View all roles",
        scope: "any",
        resource: "roles",
        action: "read",
        is_active: true,
        metadata: %{
          category: "role_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "roles.update.any",
        description: "Modify any role",
        scope: "any",
        resource: "roles",
        action: "update",
        is_active: true,
        metadata: %{
          category: "role_management",
          risk_level: "critical",
          requires_2fa: true,
          audit_required: true,
          seeded: true
        }
      },
      %{
        name: "roles.delete.any",
        description: "Delete any role",
        scope: "any",
        resource: "roles",
        action: "delete",
        is_active: true,
        metadata: %{
          category: "role_management",
          risk_level: "critical",
          requires_2fa: true,
          requires_approval: true,
          audit_required: true,
          seeded: true
        }
      },
      %{
        name: "roles.assign.any",
        description: "Assign roles to any user",
        scope: "any",
        resource: "roles",
        action: "assign",
        is_active: true,
        metadata: %{
          category: "role_management",
          risk_level: "high",
          requires_2fa: true,
          audit_required: true,
          seeded: true
        }
      },

      # Permission management
      %{
        name: "permissions.create.any",
        description: "Create new permissions",
        scope: "any",
        resource: "permissions",
        action: "create",
        is_active: true,
        metadata: %{
          category: "permission_management",
          risk_level: "critical",
          requires_2fa: true,
          requires_approval: true,
          audit_required: true,
          seeded: true
        }
      },
      %{
        name: "permissions.read.any",
        description: "View all permissions",
        scope: "any",
        resource: "permissions",
        action: "read",
        is_active: true,
        metadata: %{
          category: "permission_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "permissions.update.any",
        description: "Modify any permission",
        scope: "any",
        resource: "permissions",
        action: "update",
        is_active: true,
        metadata: %{
          category: "permission_management",
          risk_level: "critical",
          requires_2fa: true,
          requires_approval: true,
          audit_required: true,
          seeded: true
        }
      },
      %{
        name: "permissions.delete.any",
        description: "Delete any permission",
        scope: "any",
        resource: "permissions",
        action: "delete",
        is_active: true,
        metadata: %{
          category: "permission_management",
          risk_level: "critical",
          requires_2fa: true,
          requires_approval: true,
          audit_required: true,
          seeded: true
        }
      },
      %{
        name: "permissions.grant.any",
        description: "Grant permissions to roles",
        scope: "any",
        resource: "permissions",
        action: "grant",
        is_active: true,
        metadata: %{
          category: "permission_management",
          risk_level: "critical",
          requires_2fa: true,
          audit_required: true,
          seeded: true
        }
      },

      # Posts management permissions (example resource)
      %{
        name: "posts.create.any",
        description: "Create posts",
        scope: "any",
        resource: "posts",
        action: "create",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "posts.read.any",
        description: "Read any post",
        scope: "any",
        resource: "posts",
        action: "read",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "posts.update.any",
        description: "Update any post",
        scope: "any",
        resource: "posts",
        action: "update",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "medium",
          seeded: true
        }
      },
      %{
        name: "posts.update.own",
        description: "Update own posts",
        scope: "own",
        resource: "posts",
        action: "update",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "posts.delete.any",
        description: "Delete any post",
        scope: "any",
        resource: "posts",
        action: "delete",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "medium",
          seeded: true
        }
      },
      %{
        name: "posts.delete.own",
        description: "Delete own posts",
        scope: "own",
        resource: "posts",
        action: "delete",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "posts.publish.any",
        description: "Publish any post",
        scope: "any",
        resource: "posts",
        action: "publish",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "medium",
          seeded: true
        }
      },
      %{
        name: "posts.moderate.any",
        description: "Moderate posts",
        scope: "any",
        resource: "posts",
        action: "moderate",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "medium",
          requires_training: true,
          seeded: true
        }
      },

      # Settings management
      %{
        name: "settings.read.any",
        description: "View system settings",
        scope: "any",
        resource: "settings",
        action: "read",
        is_active: true,
        metadata: %{
          category: "system_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "settings.update.any",
        description: "Modify system settings",
        scope: "any",
        resource: "settings",
        action: "update",
        is_active: true,
        metadata: %{
          category: "system_management",
          risk_level: "critical",
          requires_2fa: true,
          requires_approval: true,
          audit_required: true,
          seeded: true
        }
      },

      # Audit log permissions
      %{
        name: "audit.read.any",
        description: "View audit logs",
        scope: "any",
        resource: "audit",
        action: "read",
        is_active: true,
        metadata: %{
          category: "security",
          risk_level: "medium",
          compliance_required: true,
          seeded: true
        }
      },
      %{
        name: "audit.export.any",
        description: "Export audit logs",
        scope: "any",
        resource: "audit",
        action: "export",
        is_active: true,
        metadata: %{
          category: "security",
          risk_level: "high",
          requires_2fa: true,
          compliance_required: true,
          audit_required: true,
          seeded: true
        }
      },

      # Analytics permissions
      %{
        name: "analytics.view.any",
        description: "View analytics dashboard",
        scope: "any",
        resource: "analytics",
        action: "view",
        is_active: true,
        metadata: %{
          category: "analytics",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "analytics.export.any",
        description: "Export analytics data",
        scope: "any",
        resource: "analytics",
        action: "export",
        is_active: true,
        metadata: %{
          category: "analytics",
          risk_level: "medium",
          seeded: true
        }
      },

      # API management
      %{
        name: "api.tokens.create",
        description: "Create API tokens",
        scope: "any",
        resource: "api",
        action: "create_token",
        is_active: true,
        metadata: %{
          category: "api_management",
          risk_level: "high",
          requires_2fa: true,
          seeded: true
        }
      },
      %{
        name: "api.tokens.revoke",
        description: "Revoke API tokens",
        scope: "any",
        resource: "api",
        action: "revoke_token",
        is_active: true,
        metadata: %{
          category: "api_management",
          risk_level: "high",
          requires_2fa: true,
          audit_required: true,
          seeded: true
        }
      },

      # Backup and restore
      %{
        name: "system.backup.create",
        description: "Create system backups",
        scope: "any",
        resource: "system",
        action: "backup",
        is_active: true,
        metadata: %{
          category: "system_management",
          risk_level: "high",
          requires_2fa: true,
          audit_required: true,
          seeded: true
        }
      },
      %{
        name: "system.restore.execute",
        description: "Restore from backup",
        scope: "any",
        resource: "system",
        action: "restore",
        is_active: true,
        metadata: %{
          category: "system_management",
          risk_level: "critical",
          requires_2fa: true,
          requires_approval: true,
          audit_required: true,
          maintenance_mode_required: true,
          seeded: true
        }
      },

      # Simplified permissions for common use
      %{
        name: "posts.list.any",
        description: "List all posts",
        scope: "any",
        resource: "posts",
        action: "list",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "low",
          seeded: true
        }
      },
      %{
        name: "posts.view.any",
        description: "View post details",
        scope: "any",
        resource: "posts",
        action: "view",
        is_active: true,
        metadata: %{
          category: "content_management",
          risk_level: "low",
          seeded: true
        }
      }
    ]
  end

  @doc "Returns the role definitions for seeding"
  def role_definitions do
    [
      %{
        name: "Super Administrator",
        slug: "superadmin",
        description: "Full system access with all permissions",
        is_system: true,
        is_active: true,
        metadata: %{
          level: 100,
          badge_color: "#FF0000",
          requires_2fa: true,
          max_users: 2,
          seeded: true
        }
      },
      %{
        name: "Administrator",
        slug: "admin",
        description: "Administrative access with most permissions",
        is_system: true,
        is_active: true,
        metadata: %{
          level: 90,
          badge_color: "#FF6B6B",
          requires_2fa: true,
          seeded: true
        }
      },
      %{
        name: "Moderator",
        slug: "moderator",
        description: "Content moderation and user management",
        is_system: false,
        is_active: true,
        metadata: %{
          level: 50,
          badge_color: "#4ECDC4",
          seeded: true
        }
      },
      %{
        name: "Editor",
        slug: "editor",
        description: "Content creation and editing",
        is_system: false,
        is_active: true,
        metadata: %{
          level: 30,
          badge_color: "#45B7D1",
          seeded: true
        }
      },
      %{
        name: "User",
        slug: "user",
        description: "Standard user with basic permissions",
        is_system: true,
        is_active: true,
        metadata: %{
          level: 10,
          badge_color: "#96CEB4",
          is_default: true,
          seeded: true
        }
      },
      %{
        name: "Guest",
        slug: "guest",
        description: "Limited read-only access",
        is_system: true,
        is_active: true,
        metadata: %{
          level: 1,
          badge_color: "#DDA0DD",
          is_public: true,
          seeded: true
        }
      }
    ]
  end

  @doc "Returns the user definitions for seeding"
  def user_definitions do
    [
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
          created_by: "system",
          purpose: "development"
        },
        role: "superadmin"
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
          created_by: "system",
          purpose: "development"
        },
        role: "admin"
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
          created_by: "system",
          purpose: "development"
        },
        role: "moderator"
      },
      %{
        email: "editor@example.com",
        username: "editor",
        password: "Editor123!",
        first_name: "Content",
        last_name: "Editor",
        phone: "+1234567893",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          created_by: "system",
          purpose: "development"
        },
        role: "editor"
      },
      %{
        email: "user@example.com",
        username: "testuser",
        password: "User123!",
        first_name: "Test",
        last_name: "User",
        phone: "+1234567894",
        email_verified_at: DateTime.utc_now(),
        metadata: %{
          seeded: true,
          created_by: "system",
          purpose: "development"
        },
        role: "user"
      },
      %{
        email: "guest@example.com",
        username: "guest",
        password: "Guest123!",
        first_name: "Guest",
        last_name: "User",
        phone: "+1234567895",
        metadata: %{
          seeded: true,
          created_by: "system",
          purpose: "development"
        },
        role: "guest"
      }
    ]
  end

  @doc "Returns the role-permission mappings"
  def role_permission_mappings do
    %{
      "superadmin" => [
        # All permissions - superadmin has everything
        "users.create.any",
        "users.read.any",
        "users.read.own",
        "users.update.any",
        "users.update.own",
        "users.delete.any",
        "users.delete.own",
        "roles.create.any",
        "roles.read.any",
        "roles.update.any",
        "roles.delete.any",
        "roles.assign.any",
        "permissions.create.any",
        "permissions.read.any",
        "permissions.update.any",
        "permissions.delete.any",
        "permissions.grant.any",
        "posts.create.any",
        "posts.read.any",
        "posts.update.any",
        "posts.update.own",
        "posts.delete.any",
        "posts.delete.own",
        "posts.publish.any",
        "posts.moderate.any",
        "settings.read.any",
        "settings.update.any",
        "audit.read.any",
        "audit.export.any",
        "analytics.view.any",
        "analytics.export.any",
        "api.tokens.create",
        "api.tokens.revoke",
        "system.backup.create",
        "system.restore.execute",
        "posts.list.any",
        "posts.view.any"
      ],
      "admin" => [
        # Most permissions except critical system operations
        "users.create.any",
        "users.read.any",
        "users.read.own",
        "users.update.any",
        "users.update.own",
        "users.delete.any",
        "roles.read.any",
        "roles.assign.any",
        "permissions.read.any",
        "posts.create.any",
        "posts.read.any",
        "posts.update.any",
        "posts.update.own",
        "posts.delete.any",
        "posts.delete.own",
        "posts.publish.any",
        "posts.moderate.any",
        "settings.read.any",
        "audit.read.any",
        "analytics.view.any",
        "analytics.export.any",
        "api.tokens.create",
        "api.tokens.revoke",
        "posts.list.any",
        "posts.view.any"
      ],
      "moderator" => [
        # User and content moderation
        "users.read.any",
        "users.read.own",
        "users.update.own",
        "posts.read.any",
        "posts.update.any",
        "posts.delete.any",
        "posts.moderate.any",
        "audit.read.any",
        "posts.list.any",
        "posts.view.any"
      ],
      "editor" => [
        # Content management
        "posts.create.any",
        "posts.read.any",
        "posts.update.any",
        "posts.update.own",
        "posts.delete.own",
        "posts.publish.any",
        "posts.list.any",
        "posts.view.any"
      ],
      "user" => [
        # Basic user permissions
        "users.read.own",
        "users.update.own",
        "posts.create.any",
        "posts.read.any",
        "posts.update.own",
        "posts.delete.own",
        "posts.list.any",
        "posts.view.any"
      ],
      "guest" => [
        # Read-only access
        "posts.read.any",
        "posts.list.any",
        "posts.view.any"
      ]
    }
  end
end
