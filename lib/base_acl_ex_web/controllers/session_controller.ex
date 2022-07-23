defmodule BaseAclExWeb.Controllers.SessionController do
  use BaseAclExWeb, :controller

  plug :put_view, BaseAclExWeb.Views.SessionView
  action_fallback BaseAclExWeb.FallbackController

  alias BaseAclEx.Accounts.Repositories.UserRepository

  @permitted_params ~w(uid password)s

  # %{"session" => %{ "uid" => email,"password" => password}}
  def sign_in(conn, params) do
    {uid, password} = params |> Map.take(@permitted_params)

    case UserRepository.confirm_password(uid, password) do
      {:ok, user} ->
        {:ok, jwt, _full_claims} = BaseAclEx.Guardian.encode_and_sign(user)

        conn
        |> render("sign_in.json", user: user, jwt: jwt)

      {:error, _reason} ->
        conn
        |> put_status(401)
        |> render("error.json", message: "Could not login")
    end
  end
end
