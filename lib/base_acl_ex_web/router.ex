defmodule BaseAclExWeb.Router do
  use BaseAclExWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {BaseAclExWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :api_auth do
    plug BaseAclEx.Infrastructure.Security.JWT.GuardianPipeline
    plug BaseAclEx.Infrastructure.Security.Plugs.EnsureAuthenticated
  end

  scope "/", BaseAclExWeb do
    pipe_through :browser

    get "/", PageController, :home
  end

  # API v1 routes
  scope "/api/v1", BaseAclExWeb.Api.V1 do
    pipe_through :api

    # Public authentication routes
    post "/auth/register", AuthController, :register
    post "/auth/login", AuthController, :login
    post "/auth/refresh", AuthController, :refresh
  end

  scope "/api/v1", BaseAclExWeb.Api.V1 do
    pipe_through [:api, :api_auth]

    # Protected authentication routes
    post "/auth/logout", AuthController, :logout
    get "/auth/me", AuthController, :me
    get "/auth/verify", AuthController, :verify

    # User management routes
    resources "/users", UserController, only: [:index, :show, :update, :delete] do
      get "/permissions", UserController, :permissions, as: :permissions
    end
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:base_acl_ex, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: BaseAclExWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
