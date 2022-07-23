defmodule BaseAclExWeb.Controllers.RegistrationController do
  use BaseAclExWeb, :controller

  alias BaseAclEx.Accounts.Models.User
  alias BaseAclEx.Accounts.Repositories.UserRepository

  plug :put_view, BaseAclExWeb.Views.RegistrationView
  action_fallback BaseAclExWeb.FallbackController

  def sign_up(conn, %{"user" => user_params}) do
    with {:ok, %User{} = user} <- UserRepository.create_user(user_params) do
      conn
      |> put_status(:created)
      |> put_resp_header("location", Routes.user_path(conn, :show, user))
      |> render("success.json", user: user)
    end
  end
end
