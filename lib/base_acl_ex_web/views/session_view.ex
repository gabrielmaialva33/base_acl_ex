defmodule BaseAclExWeb.Views.SessionView do
  use BaseAclExWeb, :view

  def render("sign_in.json", %{user: user, jwt: jwt}) do
    %{
      status: :ok,
      message:
        "You are successfully logged in! Add this token to authorization header to make authorized requests.",
      data: %{
        token: jwt,
        id: user.id,
        email: user.email,
        username: user.username
      }
    }
  end

  def render("error.json", %{message: message}) do
    %{
      status: :error,
      message: message
    }
  end
end
