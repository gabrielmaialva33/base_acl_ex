defmodule BaseAclExWeb.UserView do
  use BaseAclExWeb, :view
  alias BaseAclExWeb.UserView

  def render("index.json", %{users: users}) do
    %{data: render_many(users, UserView, "user.json")}
  end

  def render("show.json", %{user: user}) do
    %{data: render_one(user, UserView, "user.json")}
  end

  def render("user.json", %{user: user}) do
    %{
      id: user.id,
      firstname: user.firstname,
      lastname: user.lastname,
      username: user.username,
      email: user.email,
      password_hash: user.password_hash,
      is_deleted: user.is_deleted
    }
  end
end
