defmodule BaseAclExWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use BaseAclExWeb, :html

  @doc """
  Renders your admin layout with sidebar navigation.

  This function provides the admin dashboard layout with navigation menu,
  user controls, and responsive design.

  ## Examples

      <Layouts.admin flash={@flash} current_user={@current_user}>
        <h1>Admin Content</h1>
      </Layouts.admin>

  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :current_user, :map, default: nil, doc: "the current authenticated admin user"

  slot :inner_block, required: true

  def admin(assigns) do
    ~H"""
    <div class="drawer lg:drawer-open">
      <!-- Mobile drawer toggle -->
      <input id="drawer-toggle" type="checkbox" class="drawer-toggle" />

      <div class="drawer-content flex flex-col">
        <!-- Admin header -->
        <header class="navbar bg-base-200 shadow-sm">
          <div class="navbar-start">
            <label for="drawer-toggle" class="btn btn-ghost btn-circle drawer-button lg:hidden">
              <.icon name="hero-bars-3" class="size-6" />
            </label>
            <h1 class="text-xl font-bold ml-2 lg:ml-0">BaseAclEx Admin</h1>
          </div>

          <div class="navbar-end">
            <div class="flex items-center space-x-2">
              <.theme_toggle />

              <%= if @current_user do %>
                <div class="dropdown dropdown-end">
                  <div tabindex="0" role="button" class="btn btn-ghost btn-circle avatar">
                    <div class="w-8 rounded-full bg-primary text-primary-content flex items-center justify-center">
                      <span class="text-sm font-semibold">
                        {String.first(@current_user.name || @current_user.email) |> String.upcase()}
                      </span>
                    </div>
                  </div>
                  <ul class="menu dropdown-content bg-base-100 rounded-box z-[1] w-52 p-2 shadow-lg">
                    <li class="menu-title">
                      <span>{@current_user.name || @current_user.email}</span>
                    </li>
                    <li><a class="btn btn-ghost btn-sm" href="/admin/profile">Profile</a></li>
                    <li>
                      <a class="btn btn-ghost btn-sm" href="/admin/logout" data-method="post">
                        Logout
                      </a>
                    </li>
                  </ul>
                </div>
              <% else %>
                <a href="/admin/login" class="btn btn-primary btn-sm">Login</a>
              <% end %>
            </div>
          </div>
        </header>
        
    <!-- Main content -->
        <main class="flex-1 p-4 lg:p-6">
          <.flash_group flash={@flash} />
          {render_slot(@inner_block)}
        </main>
      </div>
      
    <!-- Sidebar -->
      <div class="drawer-side">
        <label for="drawer-toggle" aria-label="close sidebar" class="drawer-overlay"></label>
        <aside class="bg-base-100 min-h-full w-64 border-r border-base-300">
          <!-- Logo/Brand -->
          <div class="p-4 border-b border-base-300">
            <div class="flex items-center space-x-3">
              <div class="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
                <.icon name="hero-shield-check" class="size-5 text-primary-content" />
              </div>
              <div>
                <h2 class="font-bold text-lg">BaseACL</h2>
                <p class="text-xs text-base-content/70">Admin Dashboard</p>
              </div>
            </div>
          </div>
          
    <!-- Navigation Menu -->
          <nav class="p-4">
            <ul class="menu menu-vertical space-y-1">
              <li>
                <a href="/admin" class="flex items-center space-x-3 p-3 rounded-lg hover:bg-base-200">
                  <.icon name="hero-squares-2x2" class="size-5" />
                  <span>Dashboard</span>
                </a>
              </li>
              
    <!-- User Management -->
              <li>
                <details>
                  <summary class="flex items-center space-x-3 p-3 rounded-lg hover:bg-base-200">
                    <.icon name="hero-users" class="size-5" />
                    <span>User Management</span>
                  </summary>
                  <ul class="ml-8 space-y-1">
                    <li>
                      <a href="/admin/users" class="p-2 hover:bg-base-200 rounded">All Users</a>
                    </li>
                    <li>
                      <a href="/admin/users/new" class="p-2 hover:bg-base-200 rounded">Add User</a>
                    </li>
                  </ul>
                </details>
              </li>
              
    <!-- Role Management -->
              <li>
                <details>
                  <summary class="flex items-center space-x-3 p-3 rounded-lg hover:bg-base-200">
                    <.icon name="hero-user-group" class="size-5" />
                    <span>Roles</span>
                  </summary>
                  <ul class="ml-8 space-y-1">
                    <li>
                      <a href="/admin/roles" class="p-2 hover:bg-base-200 rounded">All Roles</a>
                    </li>
                    <li>
                      <a href="/admin/roles/new" class="p-2 hover:bg-base-200 rounded">Create Role</a>
                    </li>
                  </ul>
                </details>
              </li>
              
    <!-- Permission Management -->
              <li>
                <details>
                  <summary class="flex items-center space-x-3 p-3 rounded-lg hover:bg-base-200">
                    <.icon name="hero-key" class="size-5" />
                    <span>Permissions</span>
                  </summary>
                  <ul class="ml-8 space-y-1">
                    <li>
                      <a href="/admin/permissions" class="p-2 hover:bg-base-200 rounded">
                        All Permissions
                      </a>
                    </li>
                    <li>
                      <a href="/admin/permissions/new" class="p-2 hover:bg-base-200 rounded">
                        Create Permission
                      </a>
                    </li>
                  </ul>
                </details>
              </li>
              
    <!-- Monitoring -->
              <li class="pt-4">
                <div class="text-xs font-semibold text-base-content/50 uppercase tracking-wide mb-2">
                  Monitoring
                </div>
              </li>
              <li>
                <a
                  href="/admin/audit"
                  class="flex items-center space-x-3 p-3 rounded-lg hover:bg-base-200"
                >
                  <.icon name="hero-document-text" class="size-5" />
                  <span>Audit Logs</span>
                </a>
              </li>
              <li>
                <a
                  href="/admin/rate-limiting"
                  class="flex items-center space-x-3 p-3 rounded-lg hover:bg-base-200"
                >
                  <.icon name="hero-chart-bar" class="size-5" />
                  <span>Rate Limiting</span>
                </a>
              </li>
            </ul>
          </nav>
        </aside>
      </div>
    </div>
    """
  end

  # Embed all files in layouts/* within this module.
  # The default root.html.heex file contains the HTML
  # skeleton of your application, namely HTML headers
  # and other static content.
  embed_templates "layouts/*"

  @doc """
  Renders your app layout.

  This function is typically invoked from every template,
  and it often contains your application menu, sidebar,
  or similar.

  ## Examples

      <Layouts.app flash={@flash}>
        <h1>Content</h1>
      </Layouts.app>

  """
  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current [scope](https://hexdocs.pm/phoenix/scopes.html)"

  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <header class="navbar px-4 sm:px-6 lg:px-8">
      <div class="flex-1">
        <a href="/" class="flex-1 flex w-fit items-center gap-2">
          <img src={~p"/images/logo.svg"} width="36" />
          <span class="text-sm font-semibold">v{Application.spec(:phoenix, :vsn)}</span>
        </a>
      </div>
      <div class="flex-none">
        <ul class="flex flex-column px-1 space-x-4 items-center">
          <li>
            <a href="https://phoenixframework.org/" class="btn btn-ghost">Website</a>
          </li>
          <li>
            <a href="https://github.com/phoenixframework/phoenix" class="btn btn-ghost">GitHub</a>
          </li>
          <li>
            <.theme_toggle />
          </li>
          <li>
            <a href="https://hexdocs.pm/phoenix/overview.html" class="btn btn-primary">
              Get Started <span aria-hidden="true">&rarr;</span>
            </a>
          </li>
        </ul>
      </div>
    </header>

    <main class="px-4 py-20 sm:px-6 lg:px-8">
      <div class="mx-auto max-w-2xl space-y-4">
        {render_slot(@inner_block)}
      </div>
    </main>

    <.flash_group flash={@flash} />
    """
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title={gettext("We can't find the internet")}
        phx-disconnected={show(".phx-client-error #client-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={gettext("Something went wrong!")}
        phx-disconnected={show(".phx-server-error #server-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end

  @doc """
  Provides dark vs light theme toggle based on themes defined in app.css.

  See <head> in root.html.heex which applies the theme before page load.
  """
  def theme_toggle(assigns) do
    ~H"""
    <div class="card relative flex flex-row items-center border-2 border-base-300 bg-base-300 rounded-full">
      <div class="absolute w-1/3 h-full rounded-full border-1 border-base-200 bg-base-100 brightness-200 left-0 [[data-theme=light]_&]:left-1/3 [[data-theme=dark]_&]:left-2/3 transition-[left]" />

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="system"
      >
        <.icon name="hero-computer-desktop-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="light"
      >
        <.icon name="hero-sun-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="dark"
      >
        <.icon name="hero-moon-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>
    </div>
    """
  end
end
