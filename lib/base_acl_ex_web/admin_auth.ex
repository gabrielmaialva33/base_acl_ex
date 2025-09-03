defmodule BaseAclExWeb.AdminAuth do
  @moduledoc """
  Admin authentication helpers and on_mount callbacks.
  """

  import Phoenix.LiveView
  import Phoenix.Component
  alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl

  def on_mount(:default, _params, session, socket) do
    socket =
      socket
      |> assign_current_user(session)
      |> assign_flash_if_needed()

    if socket.assigns.current_user do
      {:cont, socket}
    else
      {:halt, redirect(socket, to: "/admin/login")}
    end
  end

  def on_mount(:allow_unauthenticated, _params, session, socket) do
    socket =
      socket
      |> assign_current_user(session)
      |> assign_flash_if_needed()

    {:cont, socket}
  end

  defp assign_current_user(socket, session) do
    case session["guardian_default_token"] do
      nil ->
        assign(socket, :current_user, nil)

      token ->
        case GuardianImpl.resource_from_token(token) do
          {:ok, user, _claims} ->
            assign(socket, :current_user, user)

          {:error, _reason} ->
            assign(socket, :current_user, nil)
        end
    end
  end

  defp assign_flash_if_needed(socket) do
    if Phoenix.Flash.get(socket.assigns.flash || %{}, :error) do
      socket
    else
      clear_flash(socket)
    end
  end

  @doc """
  Used for routes that require the user to be authenticated.
  """
  def require_authenticated_user(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> Phoenix.Controller.put_flash(:error, "You must log in to access this page.")
      |> Phoenix.Controller.redirect(to: "/admin/login")
      |> Plug.Conn.halt()
    end
  end

  @doc """
  Used for routes that require the user to be an admin.
  """
  def require_admin_user(conn, _opts) do
    user = conn.assigns[:current_user]

    if user && has_admin_permission?(user) do
      conn
    else
      conn
      |> Phoenix.Controller.put_flash(:error, "You don't have permission to access this area.")
      |> Phoenix.Controller.redirect(to: "/")
      |> Plug.Conn.halt()
    end
  end

  defp has_admin_permission?(user) do
    # Check if user has admin permissions by verifying role-based permissions
    # This implementation checks if the user has admin role or admin permissions
    import Ecto.Query

    admin_permission_query =
      from(p in BaseAclEx.Identity.Core.Entities.Permission,
        join: rp in "role_permissions",
        on: rp.permission_id == p.id,
        join: ur in "user_roles",
        on: ur.role_id == rp.role_id,
        where:
          ur.user_id == ^user.id and
            (p.action == "admin" or p.resource == "admin" or p.action == "manage"),
        limit: 1
      )

    BaseAclEx.Repo.exists?(admin_permission_query)
  end
end
