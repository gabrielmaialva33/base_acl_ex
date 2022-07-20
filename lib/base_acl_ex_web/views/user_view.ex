defmodule BaseAclExWeb.Views.UserView do
  use BaseAclExWeb, :view
  alias BaseAclExWeb.Views.UserView

  def render("index.json", %{users: users}) do
    %{data: render_many(users, UserView, "user.json")}
  end

  def render("show.json", %{user: user}) do
    %{data: render_one(user, UserView, "user.json")}
  end

  def render("user.json", %{user: user}) do
    %{
      id: user.id,
      fullname: "#{user.firstname} #{user.lastname}",
      firstname: user.firstname,
      lastname: user.lastname,
      username: user.username,
      email: user.email
    }
  end
end
