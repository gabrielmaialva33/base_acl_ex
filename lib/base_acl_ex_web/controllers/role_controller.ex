defmodule BaseAclExWeb.Controllers.RoleController do
  use BaseAclExWeb, :controller

  alias BaseAclEx.Accounts.Repositories.RoleRepository
  alias BaseAclEx.Accounts.Models.Role

  plug :put_view, BaseAclExWeb.Views.RoleView
  action_fallback BaseAclExWeb.FallbackController

  def index(conn, _params) do
    roles = RoleRepository.list_roles()
    render(conn, "index.json", roles: roles)
  end

  def create(conn, %{"role" => role_params}) do
    with {:ok, %Role{} = role} <- RoleRepository.create_role(role_params) do
      conn
      |> put_status(:created)
      |> put_resp_header("location", Routes.role_path(conn, :show, role))
      |> render("show.json", role: role)
    end
  end

  def show(conn, %{"id" => id}) do
    role = RoleRepository.get_role!(id)
    render(conn, "show.json", role: role)
  end

  def update(conn, %{"id" => id, "role" => role_params}) do
    role = RoleRepository.get_role!(id)

    with {:ok, %Role{} = role} <- RoleRepository.update_role(role, role_params) do
      render(conn, "show.json", role: role)
    end
  end

  def delete(conn, %{"id" => id}) do
    role = RoleRepository.get_role!(id)

    with {:ok, %Role{}} <- RoleRepository.delete_role(role) do
      send_resp(conn, :no_content, "")
    end
  end
end
