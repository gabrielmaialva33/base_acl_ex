defmodule BaseAclExWeb.Controllers.UserController do
  use BaseAclExWeb, :controller

  alias Flop
  alias BaseAclEx.Accounts.Repositories.UserRepository
  alias BaseAclEx.Accounts.Models.User
  alias BaseAclExWeb.Helpers

  plug :put_view, BaseAclExWeb.Views.UserView
  action_fallback BaseAclExWeb.FallbackController

  @permitted_params ~w(page page_size search)s

  def index(conn, params) do
    map =
      params
      |> Map.take(@permitted_params)
      |> Helpers.keys_to_atoms()
      |> Map.put(:filters, [%{field: :search, op: :=~, value: Map.get(params, "search", "")}])

    with {:ok, flop} <- Flop.validate(map, for: User) do
      {:ok, {users, meta}} = UserRepository.list_users(flop)
      render(conn, "index.json", %{users: users, meta: meta})
    end
  end

  def create(conn, %{"user" => user_params}) do
    with {:ok, %User{} = user} <- UserRepository.create_user(user_params) do
      conn
      |> put_status(:created)
      |> put_resp_header("location", Routes.user_path(conn, :show, user))
      |> render("show.json", user: user)
    end
  end

  def show(conn, %{"id" => id}) do
    user = UserRepository.get_user(id)
    render(conn, "show.json", user: user)
  end

  def update(conn, %{"id" => id, "user" => user_params}) do
    user = UserRepository.get_user(id)

    with {:ok, %User{} = user} <- UserRepository.update_user(user, user_params) do
      render(conn, "show.json", user: user)
    end
  end

  def delete(conn, %{"id" => id}) do
    user = UserRepository.get_user!(id)

    with {:ok, %User{}} <- UserRepository.delete_user(user) do
      send_resp(conn, :no_content, "")
    end
  end
end
