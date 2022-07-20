defmodule BaseAclExWeb.Views.RoleView do
  use BaseAclExWeb, :view
  alias BaseAclExWeb.Views.RoleView

  def render("index.json", %{roles: roles}) do
    %{data: render_many(roles, RoleView, "role.json")}
  end

  def render("show.json", %{role: role}) do
    %{data: render_one(role, RoleView, "role.json")}
  end

  def render("role.json", %{role: role}) do
    %{
      id: role.id,
      slug: role.slug,
      description: role.description
    }
  end
end
