defmodule BaseAclExWeb.Admin.DashboardLive do
  use BaseAclExWeb, :live_view

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.{Permission, Role}
  alias BaseAclEx.Repo

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      send(self(), :load_metrics)
    end

    socket =
      socket
      |> assign(:page_title, "Dashboard")
      |> assign(:loading, true)
      |> assign(:metrics, %{})

    {:ok, socket}
  end

  @impl true
  def handle_info(:load_metrics, socket) do
    metrics = load_dashboard_metrics()

    socket =
      socket
      |> assign(:loading, false)
      |> assign(:metrics, metrics)

    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.admin flash={@flash} current_user={@current_user}>
      <div class="space-y-6">
        <!-- Page Header -->
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-3xl font-bold text-base-content">Dashboard</h1>
            <p class="text-base-content/70 mt-1">Welcome to BaseAclEx Admin Dashboard</p>
          </div>
          <div class="badge badge-primary">
            System Status: <span class="font-semibold ml-1">Active</span>
          </div>
        </div>
        
    <!-- Metrics Cards -->
        <%= if @loading do %>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <%= for _ <- 1..4 do %>
              <div class="card bg-base-100 shadow">
                <div class="card-body">
                  <div class="flex items-center justify-between">
                    <div>
                      <div class="skeleton h-4 w-20 mb-2"></div>
                      <div class="skeleton h-8 w-16"></div>
                    </div>
                    <div class="skeleton w-12 h-12 rounded-lg"></div>
                  </div>
                </div>
              </div>
            <% end %>
          </div>
        <% else %>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <!-- Total Users -->
            <div class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
              <div class="card-body">
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-base-content/70 text-sm font-medium">Total Users</p>
                    <p class="text-3xl font-bold text-base-content">
                      {@metrics.total_users}
                    </p>
                  </div>
                  <div class="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center">
                    <.icon name="hero-users" class="size-6 text-primary" />
                  </div>
                </div>
                <div class="flex items-center mt-4 text-sm">
                  <span class="text-success">+{@metrics.new_users_this_month}</span>
                  <span class="text-base-content/70 ml-1">this month</span>
                </div>
              </div>
            </div>
            
    <!-- Total Roles -->
            <div class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
              <div class="card-body">
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-base-content/70 text-sm font-medium">Total Roles</p>
                    <p class="text-3xl font-bold text-base-content">
                      {@metrics.total_roles}
                    </p>
                  </div>
                  <div class="w-12 h-12 bg-secondary/20 rounded-lg flex items-center justify-center">
                    <.icon name="hero-user-group" class="size-6 text-secondary" />
                  </div>
                </div>
                <div class="flex items-center mt-4 text-sm">
                  <span class="text-base-content/70">Active roles</span>
                </div>
              </div>
            </div>
            
    <!-- Total Permissions -->
            <div class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
              <div class="card-body">
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-base-content/70 text-sm font-medium">Total Permissions</p>
                    <p class="text-3xl font-bold text-base-content">
                      {@metrics.total_permissions}
                    </p>
                  </div>
                  <div class="w-12 h-12 bg-accent/20 rounded-lg flex items-center justify-center">
                    <.icon name="hero-key" class="size-6 text-accent" />
                  </div>
                </div>
                <div class="flex items-center mt-4 text-sm">
                  <span class="text-base-content/70">System permissions</span>
                </div>
              </div>
            </div>
            
    <!-- API Requests -->
            <div class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
              <div class="card-body">
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-base-content/70 text-sm font-medium">API Requests</p>
                    <p class="text-3xl font-bold text-base-content">
                      {@metrics.api_requests_today}
                    </p>
                  </div>
                  <div class="w-12 h-12 bg-info/20 rounded-lg flex items-center justify-center">
                    <.icon name="hero-chart-bar-square" class="size-6 text-info" />
                  </div>
                </div>
                <div class="flex items-center mt-4 text-sm">
                  <span class="text-base-content/70">today</span>
                </div>
              </div>
            </div>
          </div>
        <% end %>
        
    <!-- Recent Activity -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- System Health -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h3 class="card-title">System Health</h3>

              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <span class="text-base-content/70">Database Status</span>
                  <div class="badge badge-success gap-2">
                    <div class="w-2 h-2 bg-success rounded-full"></div>
                    Healthy
                  </div>
                </div>

                <div class="flex items-center justify-between">
                  <span class="text-base-content/70">Cache System</span>
                  <div class="badge badge-success gap-2">
                    <div class="w-2 h-2 bg-success rounded-full"></div>
                    Active
                  </div>
                </div>

                <div class="flex items-center justify-between">
                  <span class="text-base-content/70">Rate Limiting</span>
                  <div class="badge badge-success gap-2">
                    <div class="w-2 h-2 bg-success rounded-full"></div>
                    Operational
                  </div>
                </div>
              </div>
            </div>
          </div>
          
    <!-- Quick Actions -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h3 class="card-title">Quick Actions</h3>

              <div class="grid grid-cols-1 gap-3">
                <a href="/admin/users/new" class="btn btn-outline">
                  <.icon name="hero-plus" class="size-4" /> Add New User
                </a>

                <a href="/admin/roles/new" class="btn btn-outline">
                  <.icon name="hero-plus" class="size-4" /> Create Role
                </a>

                <a href="/admin/permissions/new" class="btn btn-outline">
                  <.icon name="hero-plus" class="size-4" /> Create Permission
                </a>

                <a href="/admin/audit" class="btn btn-outline">
                  <.icon name="hero-document-text" class="size-4" /> View Audit logs
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layouts.admin>
    """
  end

  defp load_dashboard_metrics do
    # In a real application, you might want to cache these queries
    # or run them in the background to avoid blocking the LiveView

    %{
      total_users: Repo.aggregate(User, :count, :id),
      total_roles: Repo.aggregate(Role, :count, :id),
      total_permissions: Repo.aggregate(Permission, :count, :id),
      new_users_this_month: count_new_users_this_month(),
      api_requests_today: get_api_requests_today()
    }
  end

  defp count_new_users_this_month do
    start_of_month = Date.beginning_of_month(Date.utc_today())

    import Ecto.Query

    from(u in User,
      where: u.inserted_at >= ^start_of_month
    )
    |> Repo.aggregate(:count, :id)
  end

  defp get_api_requests_today do
    # This is a placeholder - in a real app you'd query your metrics system
    # or log aggregation system
    :rand.uniform(1000) + 500
  end
end
