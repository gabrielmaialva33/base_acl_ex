defmodule BaseAclEx.Infrastructure.Security.Plugs.EnsurePermissions do
  @moduledoc """
  Plug to ensure user has required permissions.
  Supports checking multiple permissions with AND/OR logic.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]
  alias BaseAclEx.Identity.Application.Services.PermissionCache

  def init(opts) do
    %{
      permissions: Keyword.get(opts, :permissions, []),
      require_all: Keyword.get(opts, :require_all, true),
      scope: Keyword.get(opts, :scope, "any")
    }
  end

  def call(conn, %{permissions: permissions} = opts) do
    user = Guardian.Plug.current_resource(conn)

    if user && has_required_permissions?(user, permissions, opts) do
      conn
    else
      conn
      |> put_status(:forbidden)
      |> put_resp_content_type("application/json")
      |> json(%{
        error: %{
          message: "Insufficient permissions",
          type: "unauthorized",
          required_permissions: permissions
        }
      })
      |> halt()
    end
  end

  defp has_required_permissions?(_user, [], _opts), do: true

  defp has_required_permissions?(user, permissions, %{require_all: true, scope: scope}) do
    Enum.all?(permissions, fn permission ->
      check_permission(user, permission, scope)
    end)
  end

  defp has_required_permissions?(user, permissions, %{require_all: false, scope: scope}) do
    Enum.any?(permissions, fn permission ->
      check_permission(user, permission, scope)
    end)
  end

  defp check_permission(user, permission, scope) do
    case PermissionCache.has_permission?(user.id, permission, scope) do
      {:ok, result} -> result
      _ -> false
    end
  end
end
