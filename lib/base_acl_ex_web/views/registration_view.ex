defmodule BaseAclExWeb.Views.RegistrationView do
  use BaseAclExWeb, :view
  alias BaseAclExWeb.Views.UserView

  def render("success.json", %{user: user}) do
    %{
      status: :ok,
      message:
        "Now you can sign in using your email and password at /api/sign_in. You will receive JWT token. Please put this token into Authorization header for all authorized requests.",
      user: render_one(user, UserView, "user.json")
    }
  end
end
