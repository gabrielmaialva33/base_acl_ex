defmodule BaseAclExWeb.Admin.RoleLive.Show do
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
    role = get_role!(id)

    socket =
      socket
      |> assign(:page_title, "Role Details")
      |> assign(:role, role)
      |> assign(:role_users, get_role_users(id))
      |> assign(:role_permissions, get_role_permissions(id))
      |> assign(:stats, get_role_stats(id))

    {:noreply, socket}
  end

  @impl true
  def handle_event("delete", %{"id" => id}, socket) do
    role = get_role!(id)

    case delete_role(role) do
      {:ok, _role} ->
        socket =
          socket
          |> put_flash(:info, "Role deleted successfully")
          |> push_navigate(to: ~p"/admin/roles")

        {:noreply, socket}

      {:error, :has_users} ->
        {:noreply, put_flash(socket, :error, "Cannot delete role that has assigned users")}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to delete role")}
    end
  end

  def handle_event("remove_user", %{"user_id" => user_id}, socket) do
    role_id = socket.assigns.role.id

    case remove_user_from_role(user_id, role_id) do
      {:ok, _} ->
        socket =
          socket
          |> put_flash(:info, "User removed from role successfully")
          |> assign(:role_users, get_role_users(role_id))
          |> assign(:stats, get_role_stats(role_id))

        {:noreply, socket}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to remove user from role")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.admin flash={@flash} current_user={@current_user}>
      <div class="space-y-6">
        <!-- Page Header -->
        <.page_header>
          <:title>{@role.name}</:title>
          <:description>Role details, users, and permissions overview</:description>
          <:action>
            <.link navigate={~p"/admin/roles"} class="btn btn-ghost">
              <.icon name="hero-arrow-left" class="size-4" /> Back to Roles
            </.link>
            <.link patch={~p"/admin/roles/#{@role}/show/edit"} class="btn btn-primary">
              <.icon name="hero-pencil" class="size-4" /> Edit Role
            </.link>
          </:action>
        </.page_header>
        
    <!-- Role Overview Card -->
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <div class="flex items-start justify-between">
              <div class="flex items-start space-x-4">
                <div class="w-16 h-16 bg-secondary/20 rounded-lg flex items-center justify-center">
                  <.icon name="hero-user-group" class="size-8 text-secondary" />
                </div>

                <div>
                  <h2 class="text-2xl font-bold">{@role.name}</h2>
                  <%= if @role.description do %>
                    <p class="text-base-content/70 text-lg mt-1">{@role.description}</p>
                  <% end %>

                  <div class="flex items-center space-x-6 mt-4">
                    <div class="text-sm">
                      <span class="text-base-content/50">Created:</span>
                      <span class="font-medium">
                        {Calendar.strftime(@role.inserted_at, "%B %d, %Y")}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              
    <!-- Actions Dropdown -->
              <div class="dropdown dropdown-end">
                <div tabindex="0" role="button" class="btn btn-ghost btn-circle">
                  <.icon name="hero-ellipsis-vertical" class="size-5" />
                </div>
                <ul class="menu dropdown-content bg-base-100 rounded-box z-[1] w-52 p-2 shadow-lg">
                  <li>
                    <.link patch={~p"/admin/roles/#{@role}/show/edit"} class="btn btn-ghost btn-sm">
                      <.icon name="hero-pencil" class="size-4" /> Edit Role
                    </.link>
                  </li>
                  <li>
                    <button
                      phx-click="delete"
                      phx-value-id={@role.id}
                      data-confirm="Are you sure you want to delete this role? This action cannot be undone."
                      class="btn btn-ghost btn-sm text-error hover:bg-error/10"
                    >
                      <.icon name="hero-trash" class="size-4" /> Delete Role
                    </button>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
        
    <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <.stat_card
            title="Assigned Users"
            value={to_string(@stats.user_count)}
            icon="hero-users"
            color="primary"
            description="active users"
          />

          <.stat_card
            title="Permissions"
            value={to_string(@stats.permission_count)}
            icon="hero-key"
            color="secondary"
            description="granted permissions"
          />

          <.stat_card
            title="Created"
            value={Calendar.strftime(@role.inserted_at, "%b %d")}
            icon="hero-calendar-days"
            color="accent"
            description={to_string(Date.diff(Date.utc_today(), Date.from_iso8601!(Calendar.strftime(@role.inserted_at, "%Y-%m-%d")))) <> " days ago"}
          />
        </div>
        
    <!-- Details Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- Assigned Users Card -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex items-center justify-between mb-4">
                <h3 class="card-title">Assigned Users</h3>
                <div class="badge badge-primary">{length(@role_users)}</div>
              </div>

              <%= if @role_users == [] do %>
                <div class="text-center py-8 text-base-content/50">
                  <.icon name="hero-users" class="size-12 mx-auto mb-2" />
                  <p>No users assigned to this role</p>
                  <p class="text-sm mt-1">Assign users through the user management interface</p>
                </div>
              <% else %>
                <div class="space-y-3 max-h-96 overflow-y-auto">
                  <div
                    :for={user <- @role_users}
                    class="flex items-center justify-between p-3 bg-base-200 rounded-lg"
                  >
                    <div class="flex items-center space-x-3">
                      <div class="avatar placeholder">
                        <div class="w-8 h-8 bg-primary text-primary-content rounded-full">
                          <span class="text-xs font-semibold">
                            {String.first(user.name || user.email) |> String.upcase()}
                          </span>
                        </div>
                      </div>
                      <div>
                        <div class="font-medium">{user.name || "No name"}</div>
                        <div class="text-sm text-base-content/70">{user.email}</div>
                      </div>
                    </div>

                    <div class="flex items-center space-x-2">
                      <.link navigate={~p"/admin/users/#{user}"} class="btn btn-ghost btn-xs">
                        <.icon name="hero-eye" class="size-3" />
                      </.link>
                      <button
                        phx-click="remove_user"
                        phx-value-user_id={user.id}
                        data-confirm="Remove this user from the role?"
                        class="btn btn-ghost btn-xs text-error hover:bg-error/10"
                      >
                        <.icon name="hero-x-mark" class="size-3" />
                      </button>
                    </div>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
          
    <!-- Role Permissions Card -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex items-center justify-between mb-4">
                <h3 class="card-title">Role Permissions</h3>
                <div class="badge badge-secondary">{length(@role_permissions)}</div>
              </div>

              <%= if @role_permissions == [] do %>
                <div class="text-center py-8 text-base-content/50">
                  <.icon name="hero-key" class="size-12 mx-auto mb-2" />
                  <p>No permissions assigned</p>
                  <p class="text-sm mt-1">Edit this role to assign permissions</p>
                </div>
              <% else %>
                <div class="space-y-2 max-h-96 overflow-y-auto">
                  <div
                    :for={permission <- @role_permissions}
                    class="flex items-center justify-between p-2 bg-base-200 rounded"
                  >
                    <div class="flex items-center space-x-2">
                      <div class="w-2 h-2 bg-secondary rounded-full"></div>
                      <span class="text-sm font-medium">{permission.action}</span>
                    </div>
                    <div class="flex items-center space-x-2">
                      <span class="text-xs text-base-content/70 bg-base-300 px-2 py-1 rounded">
                        {permission.resource}
                      </span>
                      <%= if permission.description do %>
                        <div
                          class="tooltip tooltip-left"
                          data-tip={permission.description}
                        >
                          <.icon name="hero-information-circle" class="size-3 text-base-content/50" />
                        </div>
                      <% end %>
                    </div>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        </div>
        
    <!-- Edit Role Modal -->
        <.modal
          :if={@live_action == :edit}
          id="edit-role-modal"
          show
          on_cancel={JS.patch(~p"/admin/roles/#{@role}")}
        >
          <:header>Edit Role</:header>
          <:body>
            <.live_component
              module={BaseAclExWeb.Admin.RoleLive.FormComponent}
              id={@role.id}
              title="Edit Role"
              action={:edit}
              role={@role}
              patch={~p"/admin/roles/#{@role}"}
            />
          </:body>
        </.modal>
      </div>
    </Layouts.admin>
    """
  end

  defp get_role!(id) do
    Repo.get!(Role, id)
  end

  defp get_role_users(role_id) do
    from(u in User,
      join: ur in "user_roles",
      on: ur.user_id == u.id,
      where: ur.role_id == ^role_id,
      order_by: [u.name, u.email]
    )
    |> Repo.all()
  end

  defp get_role_permissions(role_id) do
    from(p in Permission,
      join: rp in "role_permissions",
      on: rp.permission_id == p.id,
      where: rp.role_id == ^role_id,
      order_by: [p.resource, p.action]
    )
    |> Repo.all()
  end

  defp get_role_stats(role_id) do
    %{
      user_count: get_role_user_count(role_id),
      permission_count: get_role_permission_count(role_id)
    }
  end

  defp get_role_user_count(role_id) do
    from(ur in "user_roles", where: ur.role_id == ^role_id)
    |> Repo.aggregate(:count, :user_id)
  end

  defp get_role_permission_count(role_id) do
    from(rp in "role_permissions", where: rp.role_id == ^role_id)
    |> Repo.aggregate(:count, :permission_id)
  end

  defp delete_role(role) do
    user_count = get_role_user_count(role.id)

    if user_count > 0 do
      {:error, :has_users}
    else
      perform_role_deletion(role)
    end
  end

  defp perform_role_deletion(role) do
    Repo.transaction(fn ->
      # Remove permission assignments first
      from(rp in "role_permissions", where: rp.role_id == ^role.id)
      |> Repo.delete_all()

      # Delete the role
      case Repo.delete(role) do
        {:ok, deleted_role} -> deleted_role
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  defp remove_user_from_role(user_id, role_id) do
    from(ur in "user_roles",
      where: ur.user_id == ^user_id and ur.role_id == ^role_id
    )
    |> Repo.delete_all()
    |> case do
      {1, _} -> {:ok, :removed}
      _ -> {:error, :not_found}
    end
  end
end
