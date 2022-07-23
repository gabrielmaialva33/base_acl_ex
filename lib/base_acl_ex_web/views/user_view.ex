defmodule BaseAclExWeb.Views.UserView do
  use BaseAclExWeb, :view
  alias BaseAclExWeb.Views.{UserView, RoleView, MetaView}

  def render("index.json", %{users: users, meta: meta}) do
    %{
      data: render_many(users, UserView, "user.json"),
      __meta__: MetaView.render("meta.json", %{meta: meta})
    }
  end

  def render("show.json", %{user: user}) do
    %{data: render_one(user, UserView, "user.json")}
  end

  def render("user.json", %{user: user}) do
    %{
      id: user.id,
      full_name: "#{user.first_name} #{user.last_name}",
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      email: user.email,
      is_blocked: user.is_blocked,
      is_online: user.is_online,
      roles: render_many(user.roles, RoleView, "role.json"),
      inserted_at: user.inserted_at,
      updated_at: user.updated_at
    }
  end
end
