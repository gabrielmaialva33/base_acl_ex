defmodule BaseAclEx.Identity.Core.Aggregates.PermissionAggregate do
  @moduledoc """
  Aggregate root for managing user permissions and roles.
  This aggregate ensures consistency in permission assignments.
  """

  use Ecto.Schema
  import Ecto.Changeset
  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.{Permission, Role}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  embedded_schema do
    field :user_id, :binary_id
    field :roles, {:array, :map}, default: []
    field :direct_permissions, {:array, :map}, default: []
    field :effective_permissions, {:array, :map}, default: []
    field :domain_events, {:array, :map}, default: []
  end

  @doc """
  Assigns a role to a user.
  """
  def assign_role(%__MODULE__{} = aggregate, %Role{} = role, opts \\ []) do
    granted_by = Keyword.get(opts, :granted_by)
    expires_at = Keyword.get(opts, :expires_at)
    scope = Keyword.get(opts, :scope, "global")
    reason = Keyword.get(opts, :reason)

    if role_already_assigned?(aggregate, role.id) do
      {:error, :role_already_assigned}
    else
      role_assignment = %{
        role_id: role.id,
        role_slug: role.slug,
        granted_by_id: granted_by,
        granted_at: DateTime.utc_now(),
        expires_at: expires_at,
        scope: scope,
        reason: reason,
        is_active: true
      }

      event = create_role_assigned_event(aggregate.user_id, role, opts)

      aggregate
      |> Map.update!(:roles, &[role_assignment | &1])
      |> add_domain_event(event)
      |> recalculate_effective_permissions()

      {:ok, aggregate}
    end
  end

  @doc """
  Removes a role from a user.
  """
  def revoke_role(%__MODULE__{} = aggregate, role_id, opts \\ []) do
    revoked_by = Keyword.get(opts, :revoked_by)
    reason = Keyword.get(opts, :reason)

    if role_assigned?(aggregate, role_id) do
      event = create_role_revoked_event(aggregate.user_id, role_id, opts)

      aggregate =
        aggregate
        |> Map.update!(:roles, &Enum.reject(&1, fn r -> r.role_id == role_id end))
        |> add_domain_event(event)
        |> recalculate_effective_permissions()

      {:ok, aggregate}
    else
      {:error, :role_not_found}
    end
  end

  @doc """
  Grants a direct permission to a user.
  """
  def grant_permission(%__MODULE__{} = aggregate, %Permission{} = permission, opts \\ []) do
    granted_by = Keyword.get(opts, :granted_by)
    expires_at = Keyword.get(opts, :expires_at)
    scope = Keyword.get(opts, :scope, "global")
    conditions = Keyword.get(opts, :conditions, %{})
    reason = Keyword.get(opts, :reason)

    if permission_already_granted?(aggregate, permission.id) do
      {:error, :permission_already_granted}
    else
      permission_grant = %{
        permission_id: permission.id,
        permission_name: Permission.full_name(permission),
        granted_by_id: granted_by,
        granted_at: DateTime.utc_now(),
        expires_at: expires_at,
        scope: scope,
        conditions: conditions,
        reason: reason,
        is_granted: true,
        is_active: true
      }

      event = create_permission_granted_event(aggregate.user_id, permission, opts)

      aggregate =
        aggregate
        |> Map.update!(:direct_permissions, &[permission_grant | &1])
        |> add_domain_event(event)
        |> recalculate_effective_permissions()

      {:ok, aggregate}
    end
  end

  @doc """
  Revokes a direct permission from a user.
  """
  def revoke_permission(%__MODULE__{} = aggregate, permission_id, opts \\ []) do
    revoked_by = Keyword.get(opts, :revoked_by)
    reason = Keyword.get(opts, :reason)

    case find_permission(aggregate, permission_id) do
      nil ->
        {:error, :permission_not_found}

      permission ->
        updated_permission =
          Map.merge(permission, %{
            is_granted: false,
            is_active: false,
            revoked_at: DateTime.utc_now(),
            revoked_by_id: revoked_by,
            revoke_reason: reason
          })

        event = create_permission_revoked_event(aggregate.user_id, permission_id, opts)

        aggregate =
          aggregate
          |> update_permission(permission_id, updated_permission)
          |> add_domain_event(event)
          |> recalculate_effective_permissions()

        {:ok, aggregate}
    end
  end

  @doc """
  Checks if a user has a specific permission.
  """
  def has_permission?(%__MODULE__{} = aggregate, permission_name, scope \\ "any") do
    Enum.any?(aggregate.effective_permissions, fn perm ->
      perm.name == permission_name &&
        scope_satisfies?(perm.scope, scope) &&
        permission_active?(perm)
    end)
  end

  @doc """
  Gets all active permissions for a user.
  """
  def get_active_permissions(%__MODULE__{} = aggregate) do
    aggregate.effective_permissions
    |> Enum.filter(&permission_active?/1)
  end

  @doc """
  Gets all roles assigned to a user.
  """
  def get_roles(%__MODULE__{} = aggregate) do
    aggregate.roles
    |> Enum.filter(&role_active?/1)
  end

  @doc """
  Checks if a role is assigned to the user.
  """
  def role_assigned?(%__MODULE__{} = aggregate, role_id) do
    Enum.any?(aggregate.roles, fn r -> r.role_id == role_id && role_active?(r) end)
  end

  @doc """
  Loads permissions from roles and direct assignments.
  """
  def load_permissions(%__MODULE__{} = aggregate, role_permissions) do
    # Combine role permissions with direct permissions
    all_permissions = combine_permissions(aggregate, role_permissions)

    %{aggregate | effective_permissions: all_permissions}
  end

  # Private functions

  defp role_already_assigned?(aggregate, role_id) do
    Enum.any?(aggregate.roles, fn r -> r.role_id == role_id && r.is_active end)
  end

  defp permission_already_granted?(aggregate, permission_id) do
    Enum.any?(aggregate.direct_permissions, fn p ->
      p.permission_id == permission_id && p.is_granted && p.is_active
    end)
  end

  defp find_permission(aggregate, permission_id) do
    Enum.find(aggregate.direct_permissions, fn p -> p.permission_id == permission_id end)
  end

  defp update_permission(aggregate, permission_id, updated_permission) do
    permissions =
      Enum.map(aggregate.direct_permissions, fn p ->
        if p.permission_id == permission_id, do: updated_permission, else: p
      end)

    %{aggregate | direct_permissions: permissions}
  end

  defp recalculate_effective_permissions(aggregate) do
    # In a real implementation, this would fetch role permissions
    # and combine them with direct permissions
    aggregate
  end

  defp combine_permissions(aggregate, role_permissions) do
    # Direct permissions take precedence over role permissions
    direct =
      aggregate.direct_permissions
      |> Enum.filter(&(&1.is_granted && &1.is_active))

    role_perms =
      role_permissions
      |> Enum.filter(fn p ->
        not Enum.any?(direct, &(&1.permission_id == p.permission_id))
      end)

    direct ++ role_perms
  end

  defp permission_active?(permission) do
    is_active = Map.get(permission, :is_active, true)
    is_granted = Map.get(permission, :is_granted, true)
    expires_at = Map.get(permission, :expires_at)

    is_active && is_granted && not expired?(expires_at)
  end

  defp role_active?(role) do
    is_active = Map.get(role, :is_active, true)
    expires_at = Map.get(role, :expires_at)

    is_active && not expired?(expires_at)
  end

  defp expired?(nil), do: false

  defp expired?(expires_at) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  defp scope_satisfies?(user_scope, required_scope) do
    # Simplified scope checking - in reality would be more complex
    user_scope == required_scope ||
      user_scope == "global" ||
      (user_scope == "any" && required_scope != "global")
  end

  defp add_domain_event(aggregate, event) do
    Map.update!(aggregate, :domain_events, &[event | &1])
  end

  # Event creation functions

  defp create_role_assigned_event(user_id, role, opts) do
    %{
      type: "role_assigned",
      aggregate_id: user_id,
      occurred_at: DateTime.utc_now(),
      payload: %{
        user_id: user_id,
        role_id: role.id,
        role_slug: role.slug,
        granted_by: Keyword.get(opts, :granted_by),
        expires_at: Keyword.get(opts, :expires_at),
        scope: Keyword.get(opts, :scope, "global"),
        reason: Keyword.get(opts, :reason)
      }
    }
  end

  defp create_role_revoked_event(user_id, role_id, opts) do
    %{
      type: "role_revoked",
      aggregate_id: user_id,
      occurred_at: DateTime.utc_now(),
      payload: %{
        user_id: user_id,
        role_id: role_id,
        revoked_by: Keyword.get(opts, :revoked_by),
        reason: Keyword.get(opts, :reason)
      }
    }
  end

  defp create_permission_granted_event(user_id, permission, opts) do
    %{
      type: "permission_granted",
      aggregate_id: user_id,
      occurred_at: DateTime.utc_now(),
      payload: %{
        user_id: user_id,
        permission_id: permission.id,
        permission_name: Permission.full_name(permission),
        granted_by: Keyword.get(opts, :granted_by),
        expires_at: Keyword.get(opts, :expires_at),
        scope: Keyword.get(opts, :scope, "global"),
        conditions: Keyword.get(opts, :conditions, %{}),
        reason: Keyword.get(opts, :reason)
      }
    }
  end

  defp create_permission_revoked_event(user_id, permission_id, opts) do
    %{
      type: "permission_revoked",
      aggregate_id: user_id,
      occurred_at: DateTime.utc_now(),
      payload: %{
        user_id: user_id,
        permission_id: permission_id,
        revoked_by: Keyword.get(opts, :revoked_by),
        reason: Keyword.get(opts, :reason)
      }
    }
  end
end
