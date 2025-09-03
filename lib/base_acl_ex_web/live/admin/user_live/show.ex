defmodule BaseAclExWeb.Admin.UserLive.Show do
  use BaseAclExWeb, :live_view

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.{Permission, Role}
  alias BaseAclEx.Repo
  import Ecto.Query
  import BaseAclExWeb.AdminComponents

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket}
  end

  @impl true
  def handle_params(%{"id" => id}, _, socket) do
    user = get_user_with_details!(id)

    socket =
      socket
      |> assign(:page_title, "User Details")
      |> assign(:user, user)
      |> assign(:user_roles, get_user_roles(id))
      |> assign(:user_permissions, get_user_permissions(id))

    {:noreply, socket}
  end

  @impl true
  def handle_event("delete", %{"id" => id}, socket) do
    user = get_user!(id)

    case Repo.delete(user) do
      {:ok, _user} ->
        socket =
          socket
          |> put_flash(:info, "User deleted successfully")
          |> push_navigate(to: ~p"/admin/users")

        {:noreply, socket}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to delete user")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.admin flash={@flash} current_user={@current_user}>
      <div class="space-y-6">
        <!-- Page Header -->
        <.page_header>
          <:title>{@user.name || @user.email}</:title>
          <:description>User details and permissions overview</:description>
          <:action>
            <.link navigate={~p"/admin/users"} class="btn btn-ghost">
              <.icon name="hero-arrow-left" class="size-4" /> Back to Users
            </.link>
            <.link patch={~p"/admin/users/#{@user}/show/edit"} class="btn btn-primary">
              <.icon name="hero-pencil" class="size-4" /> Edit User
            </.link>
          </:action>
        </.page_header>
        
    <!-- User Profile Card -->
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <div class="flex items-start space-x-6">
              <!-- Avatar -->
              <div class="avatar placeholder">
                <div class="w-20 h-20 bg-primary text-primary-content rounded-full">
                  <span class="text-2xl font-bold">
                    {String.first(@user.name || @user.email) |> String.upcase()}
                  </span>
                </div>
              </div>
              
    <!-- User Info -->
              <div class="flex-1">
                <h2 class="text-2xl font-bold">{@user.name || "No name set"}</h2>
                <p class="text-base-content/70 text-lg">{@user.email}</p>

                <div class="flex items-center space-x-4 mt-4">
                  <div class="badge badge-success gap-2">
                    <div class="w-2 h-2 bg-success rounded-full"></div>
                    Active
                  </div>

                  <div class="text-sm text-base-content/70">
                    Created {Calendar.strftime(@user.inserted_at, "%B %d, %Y")}
                  </div>
                </div>
              </div>
              
    <!-- Actions -->
              <div class="dropdown dropdown-end">
                <div tabindex="0" role="button" class="btn btn-ghost btn-circle">
                  <.icon name="hero-ellipsis-vertical" class="size-5" />
                </div>
                <ul class="menu dropdown-content bg-base-100 rounded-box z-[1] w-52 p-2 shadow-lg">
                  <li>
                    <.link patch={~p"/admin/users/#{@user}/show/edit"} class="btn btn-ghost btn-sm">
                      <.icon name="hero-pencil" class="size-4" /> Edit User
                    </.link>
                  </li>
                  <li>
                    <button
                      phx-click="delete"
                      phx-value-id={@user.id}
                      data-confirm="Are you sure you want to delete this user?"
                      class="btn btn-ghost btn-sm text-error hover:bg-error/10"
                    >
                      <.icon name="hero-trash" class="size-4" /> Delete User
                    </button>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
        
    <!-- User Details Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- Roles Card -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex items-center justify-between mb-4">
                <h3 class="card-title">Assigned Roles</h3>
                <div class="badge badge-primary">{length(@user_roles)}</div>
              </div>

              <%= if @user_roles == [] do %>
                <div class="text-center py-8 text-base-content/50">
                  <.icon name="hero-user-group" class="size-12 mx-auto mb-2" />
                  <p>No roles assigned</p>
                </div>
              <% else %>
                <div class="space-y-2">
                  <div
                    :for={role <- @user_roles}
                    class="flex items-center justify-between p-3 bg-base-200 rounded-lg"
                  >
                    <div class="flex items-center space-x-3">
                      <div class="w-2 h-2 bg-primary rounded-full"></div>
                      <span class="font-medium">{role.name}</span>
                    </div>
                    <%= if role.description do %>
                      <span class="text-xs text-base-content/70 truncate max-w-32">
                        {role.description}
                      </span>
                    <% end %>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
          
    <!-- Permissions Card -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex items-center justify-between mb-4">
                <h3 class="card-title">Effective Permissions</h3>
                <div class="badge badge-secondary">{length(@user_permissions)}</div>
              </div>

              <%= if @user_permissions == [] do %>
                <div class="text-center py-8 text-base-content/50">
                  <.icon name="hero-key" class="size-12 mx-auto mb-2" />
                  <p>No permissions granted</p>
                </div>
              <% else %>
                <div class="space-y-2 max-h-64 overflow-y-auto">
                  <div
                    :for={permission <- @user_permissions}
                    class="flex items-center justify-between p-2 bg-base-200 rounded"
                  >
                    <div class="flex items-center space-x-2">
                      <div class="w-1.5 h-1.5 bg-secondary rounded-full"></div>
                      <span class="text-sm font-medium">{permission.action}</span>
                    </div>
                    <span class="text-xs text-base-content/70 bg-base-300 px-2 py-1 rounded">
                      {permission.resource}
                    </span>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        </div>
        
    <!-- Activity Timeline (Placeholder) -->
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h3 class="card-title mb-4">Recent Activity</h3>

            <div class="text-center py-8 text-base-content/50">
              <.icon name="hero-clock" class="size-12 mx-auto mb-2" />
              <p>Activity tracking coming soon</p>
            </div>
          </div>
        </div>
        
    <!-- Edit User Modal -->
        <.modal
          :if={@live_action == :edit}
          id="edit-user-modal"
          show
          on_cancel={JS.patch(~p"/admin/users/#{@user}")}
        >
          <:header>Edit User</:header>
          <:body>
            <.live_component
              module={BaseAclExWeb.Admin.UserLive.FormComponent}
              id={@user.id}
              title="Edit User"
              action={:edit}
              user={@user}
              patch={~p"/admin/users/#{@user}"}
            />
          </:body>
        </.modal>
      </div>
    </Layouts.admin>
    """
  end

  defp get_user_with_details!(id) do
    Repo.get!(User, id)
  end

  defp get_user!(id) do
    Repo.get!(User, id)
  end

  defp get_user_roles(user_id) do
    from(r in Role,
      join: ur in "user_roles",
      on: ur.role_id == r.id,
      where: ur.user_id == ^user_id,
      order_by: r.name
    )
    |> Repo.all()
  end

  defp get_user_permissions(user_id) do
    from(p in Permission,
      join: rp in "role_permissions",
      on: rp.permission_id == p.id,
      join: ur in "user_roles",
      on: ur.role_id == rp.role_id,
      where: ur.user_id == ^user_id,
      distinct: true,
      order_by: [p.resource, p.action]
    )
    |> Repo.all()
  end
end
