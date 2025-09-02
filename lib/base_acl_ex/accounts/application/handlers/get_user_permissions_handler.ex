defmodule BaseAclEx.Accounts.Application.Handlers.GetUserPermissionsHandler do
  @moduledoc """
  Handler for retrieving user permissions query.
  """

  use BaseAclEx.SharedKernel.CQRS.QueryHandler

  alias BaseAclEx.Accounts.Application.Queries.GetUserPermissionsQuery
  alias BaseAclEx.Identity.Application.Services.PermissionCache
  alias BaseAclEx.Identity.Core.Aggregates.PermissionAggregate

  @impl true
  def execute(%GetUserPermissionsQuery{} = query) do
    # Try cache first
    case PermissionCache.get_user_permissions(query.user_id) do
      {:ok, permissions} when is_list(permissions) ->
        filtered = filter_permissions(permissions, query)
        {:ok, filtered}

      _ ->
        # Load from database
        load_permissions_from_db(query)
    end
  end

  defp load_permissions_from_db(query) do
    # Create permission aggregate for the user
    aggregate = %PermissionAggregate{
      user_id: query.user_id,
      roles: [],
      direct_permissions: [],
      effective_permissions: []
    }

    # Load roles and permissions
    aggregate = load_user_roles(aggregate)
    aggregate = load_direct_permissions(aggregate)
    aggregate = calculate_effective_permissions(aggregate)

    permissions = PermissionAggregate.get_active_permissions(aggregate)

    # Cache the permissions
    PermissionCache.set_user_permissions(query.user_id, permissions)

    # Filter based on query parameters
    filtered = filter_permissions(permissions, query)
    {:ok, filtered}
  end

  defp load_user_roles(aggregate) do
    # Load user roles from database
    # This would query user_roles table
    aggregate
  end

  defp load_direct_permissions(aggregate) do
    # Load direct user permissions from database
    # This would query user_permissions table
    aggregate
  end

  defp calculate_effective_permissions(aggregate) do
    # Calculate effective permissions from roles and direct assignments
    aggregate
  end

  defp filter_permissions(permissions, query) do
    permissions
    |> maybe_filter_by_scope(query.scope)
    |> maybe_filter_active_only(query.active_only)
    |> maybe_exclude_inherited(query.include_inherited)
    |> format_permission_response()
  end

  defp maybe_filter_by_scope(permissions, "any"), do: permissions

  defp maybe_filter_by_scope(permissions, scope) do
    Enum.filter(permissions, fn perm ->
      perm_scope = Map.get(perm, :scope) || Map.get(perm, "scope") || "any"
      scope_matches?(perm_scope, scope)
    end)
  end

  defp scope_matches?(perm_scope, required_scope) do
    perm_scope == required_scope ||
      perm_scope == "global" ||
      (perm_scope == "any" && required_scope != "global")
  end

  defp maybe_filter_active_only(permissions, false), do: permissions

  defp maybe_filter_active_only(permissions, true) do
    Enum.filter(permissions, fn perm ->
      is_active = Map.get(perm, :is_active, true)
      expires_at = Map.get(perm, :expires_at)

      is_active && not expired?(expires_at)
    end)
  end

  defp maybe_exclude_inherited(permissions, true), do: permissions

  defp maybe_exclude_inherited(permissions, false) do
    Enum.filter(permissions, fn perm ->
      Map.get(perm, :is_direct, false)
    end)
  end

  defp expired?(nil), do: false

  defp expired?(expires_at) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  defp format_permission_response(permissions) do
    Enum.map(permissions, fn perm ->
      %{
        name: Map.get(perm, :name) || Map.get(perm, :permission_name),
        resource: Map.get(perm, :resource),
        action: Map.get(perm, :action),
        context: Map.get(perm, :context) || Map.get(perm, :scope) || "any",
        granted_at: Map.get(perm, :granted_at),
        expires_at: Map.get(perm, :expires_at),
        source: if(Map.get(perm, :is_direct), do: "direct", else: "role")
      }
    end)
  end
end
