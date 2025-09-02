defmodule BaseAclEx.Infrastructure.Security.Plugs.EnsureAuthenticated do
  @moduledoc """
  Plug to ensure user is authenticated.
  Halts connection with 401 if no user is present.
  """
  
  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]
  
  def init(opts), do: opts
  
  def call(conn, _opts) do
    if Guardian.Plug.current_resource(conn) do
      conn
    else
      conn
      |> put_status(:unauthorized)
      |> put_resp_content_type("application/json")
      |> json(%{
        error: %{
          message: "Authentication required",
          type: "unauthenticated"
        }
      })
      |> halt()
    end
  end
end