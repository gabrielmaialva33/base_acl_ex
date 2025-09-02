defmodule BaseAclExWeb.PageController do
  use BaseAclExWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
