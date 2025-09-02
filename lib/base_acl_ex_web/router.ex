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

    # Token management routes
    get "/auth/devices", AuthController, :devices
    delete "/auth/devices/:device_id", AuthController, :revoke_device
    get "/auth/stats", AuthController, :token_stats

    # User management routes
    resources "/users", UserController, only: [:index, :show, :update, :delete] do
      get "/permissions", UserController, :permissions, as: :permissions
    end

    # Role management routes
    resources "/roles", RoleController, only: [:index, :show, :create, :update, :delete] do
      get "/users", RoleController, :users, as: :users
      post "/users/:user_id", RoleController, :assign_user, as: :assign_user
      delete "/users/:user_id", RoleController, :remove_user, as: :remove_user
    end

    # Permission management routes
    resources "/permissions", PermissionController,
      only: [:index, :show, :create, :update, :delete] do
      get "/roles", PermissionController, :roles, as: :roles
      post "/roles/:role_id", PermissionController, :assign_role, as: :assign_role
      delete "/roles/:role_id", PermissionController, :remove_role, as: :remove_role
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
