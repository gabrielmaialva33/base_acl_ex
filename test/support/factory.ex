defmodule BaseAclEx.Factory do
  @moduledoc """
  Test data factory for creating test entities.
  Provides consistent and flexible test data generation.
  """

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.{Permission, Role, RolePermission, UserRole}
  alias BaseAclEx.Repo

  @doc """
  Creates a valid user with default attributes.
  """
  def build_user(attrs \\ %{}) do
    defaults = %{
      email: unique_email(),
      password: "SecurePass123!",
      password_hash: "$argon2id$v=19$m=65536,t=1,p=1$SomeHashedPassword",
      first_name: "John",
      last_name: "Doe",
      username: unique_username(),
      phone: "+1234567890",
      is_active: true,
      is_deleted: false,
      email_verified_at: DateTime.utc_now(),
      failed_login_attempts: 0,
      two_factor_enabled: false,
      metadata: %{},
      preferences: %{}
    }

    struct!(User, Map.merge(defaults, attrs))
  end

  @doc """
  Creates and inserts a user into the database.
  """
  def insert_user(attrs \\ %{}) do
    attrs
    |> build_user()
    |> Repo.insert!()
  end

  @doc """
  Creates a locked user (failed login attempts).
  """
  def build_locked_user(attrs \\ %{}) do
    build_user(
      Map.merge(attrs, %{
        failed_login_attempts: 5,
        locked_until: DateTime.add(DateTime.utc_now(), 900, :second)
      })
    )
  end

  @doc """
  Creates a soft-deleted user.
  """
  def build_deleted_user(attrs \\ %{}) do
    build_user(
      Map.merge(attrs, %{
        deleted_at: DateTime.utc_now(),
        is_deleted: true
      })
    )
  end

  @doc """
  Creates an unverified user.
  """
  def build_unverified_user(attrs \\ %{}) do
    build_user(Map.merge(attrs, %{email_verified_at: nil}))
  end

  @doc """
  Creates a user with two-factor authentication enabled.
  """
  def build_2fa_user(attrs \\ %{}) do
    build_user(
      Map.merge(attrs, %{
        two_factor_enabled: true,
        two_factor_secret: "JBSWY3DPEHPK3PXP"
      })
    )
  end

  @doc """
  Creates a valid permission with default attributes.
  """
  def build_permission(attrs \\ %{}) do
    resource = Map.get(attrs, :resource, "posts")
    action = Map.get(attrs, :action, "read")
    context = Map.get(attrs, :context, "any")

    defaults = %{
      resource: resource,
      action: action,
      context: context,
      name: "#{resource}.#{action}.#{context}",
      description: "Permission to #{action} #{resource}",
      category: "content",
      is_active: true,
      is_system: false,
      requires_ownership: false,
      requires_two_factor: false,
      risk_level: "low",
      conditions: %{},
      dependencies: [],
      metadata: %{}
    }

    struct!(Permission, Map.merge(defaults, attrs))
  end

  @doc """
  Creates and inserts a permission into the database.
  """
  def insert_permission(attrs \\ %{}) do
    attrs
    |> build_permission()
    |> Repo.insert!()
  end

  @doc """
  Creates a system permission (high-risk).
  """
  def build_system_permission(attrs \\ %{}) do
    build_permission(
      Map.merge(attrs, %{
        resource: "permissions",
        action: "delete",
        is_system: true,
        risk_level: "critical"
      })
    )
  end

  @doc """
  Creates a wildcard permission.
  """
  def build_wildcard_permission(attrs \\ %{}) do
    build_permission(
      Map.merge(attrs, %{
        resource: "posts",
        action: "*",
        context: "any"
      })
    )
  end

  @doc """
  Creates an ownership-required permission.
  """
  def build_ownership_permission(attrs \\ %{}) do
    build_permission(
      Map.merge(attrs, %{
        context: "own",
        requires_ownership: true
      })
    )
  end

  @doc """
  Creates a valid role with default attributes.
  """
  def build_role(attrs \\ %{}) do
    defaults = %{
      name: unique_role_name(),
      description: "Test role",
      is_active: true,
      is_system: false,
      level: 1,
      metadata: %{}
    }

    struct!(Role, Map.merge(defaults, attrs))
  end

  @doc """
  Creates and inserts a role into the database.
  """
  def insert_role(attrs \\ %{}) do
    attrs
    |> build_role()
    |> Repo.insert!()
  end

  @doc """
  Creates a system role.
  """
  def build_system_role(attrs \\ %{}) do
    build_role(
      Map.merge(attrs, %{
        name: "system_admin",
        is_system: true,
        level: 100
      })
    )
  end

  @doc """
  Creates a role permission association.
  """
  def build_role_permission(role, permission, attrs \\ %{}) do
    defaults = %{
      role_id: role.id,
      permission_id: permission.id,
      granted_at: DateTime.utc_now(),
      granted_by: Ecto.UUID.generate(),
      conditions: %{},
      metadata: %{}
    }

    struct!(RolePermission, Map.merge(defaults, attrs))
  end

  @doc """
  Creates and inserts a role permission association.
  """
  def insert_role_permission(role, permission, attrs \\ %{}) do
    attrs
    |> build_role_permission(role, permission)
    |> Repo.insert!()
  end

  @doc """
  Creates a user role association.
  """
  def build_user_role(user, role, attrs \\ %{}) do
    defaults = %{
      user_id: user.id,
      role_id: role.id,
      assigned_at: DateTime.utc_now(),
      assigned_by: Ecto.UUID.generate(),
      expires_at: nil,
      is_active: true,
      metadata: %{}
    }

    struct!(UserRole, Map.merge(defaults, attrs))
  end

  @doc """
  Creates and inserts a user role association.
  """
  def insert_user_role(user, role, attrs \\ %{}) do
    attrs
    |> build_user_role(user, role)
    |> Repo.insert!()
  end

  @doc """
  Creates a complete user with role and permissions setup.
  """
  def create_user_with_permissions(permissions_list \\ ["posts.read.any"]) do
    user = insert_user()
    role = insert_role(%{name: "test_role"})
    insert_user_role(user, role)

    Enum.each(permissions_list, fn permission_string ->
      [resource, action, context] = String.split(permission_string, ".")

      permission =
        insert_permission(%{
          resource: resource,
          action: action,
          context: context
        })

      insert_role_permission(role, permission)
    end)

    user
  end

  @doc """
  Creates an admin user with system permissions.
  """
  def create_admin_user(attrs \\ %{}) do
    admin_permissions = [
      "users.read.any",
      "users.create.any",
      "users.update.any",
      "users.delete.any",
      "roles.read.any",
      "roles.create.any",
      "roles.update.any",
      "permissions.read.any"
    ]

    user = insert_user(attrs)
    role = insert_role(%{name: "admin", level: 50})
    insert_user_role(user, role)

    Enum.each(admin_permissions, fn permission_string ->
      [resource, action, context] = String.split(permission_string, ".")

      permission =
        insert_permission(%{
          resource: resource,
          action: action,
          context: context
        })

      insert_role_permission(role, permission)
    end)

    user
  end

  # Private helper functions

  defp unique_email do
    "user#{System.unique_integer([:positive])}@example.com"
  end

  defp unique_username do
    "user#{System.unique_integer([:positive])}"
  end

  defp unique_role_name do
    "role_#{System.unique_integer([:positive])}"
  end
end
