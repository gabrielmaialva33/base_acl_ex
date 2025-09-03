defmodule BaseAclExWeb.Admin.PermissionLive.Show do
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
    permission = get_permission!(id)

    socket =
      socket
      |> assign(:page_title, "Permission Details")
      |> assign(:permission, permission)
      |> assign(:assigned_roles, get_permission_roles(id))
      |> assign(:effective_users, get_users_with_permission(id))
      |> assign(:stats, get_permission_stats(id))

    {:noreply, socket}
  end

  @impl true
  def handle_event("delete", %{"id" => id}, socket) do
    permission = get_permission!(id)

    case delete_permission(permission) do
      {:ok, _permission} ->
        socket =
          socket
          |> put_flash(:info, "Permission deleted successfully")
          |> push_navigate(to: ~p"/admin/permissions")

        {:noreply, socket}

      {:error, :has_roles} ->
        {:noreply,
         put_flash(socket, :error, "Cannot delete permission that is assigned to roles")}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to delete permission")}
    end
  end

  def handle_event("remove_role", %{"role_id" => role_id}, socket) do
    permission_id = socket.assigns.permission.id

    case remove_permission_from_role(permission_id, role_id) do
      {:ok, _} ->
        socket =
          socket
          |> put_flash(:info, "Permission removed from role successfully")
          |> assign(:assigned_roles, get_permission_roles(permission_id))
          |> assign(:effective_users, get_users_with_permission(permission_id))
          |> assign(:stats, get_permission_stats(permission_id))

        {:noreply, socket}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to remove permission from role")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.admin flash={@flash} current_user={@current_user}>
      <div class="space-y-6">
        <!-- Page Header -->
        <.page_header>
          <:title>{@permission.action} • {@permission.resource}</:title>
          <:description>Permission details and assignment overview</:description>
          <:action>
            <.link navigate={~p"/admin/permissions"} class="btn btn-ghost">
              <.icon name="hero-arrow-left" class="size-4" /> Back to Permissions
            </.link>
            <.link patch={~p"/admin/permissions/#{@permission}/show/edit"} class="btn btn-primary">
              <.icon name="hero-pencil" class="size-4" /> Edit Permission
            </.link>
          </:action>
        </.page_header>
        
    <!-- Permission Overview Card -->
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <div class="flex items-start justify-between">
              <div class="flex items-start space-x-4">
                <div class="w-16 h-16 bg-accent/20 rounded-lg flex items-center justify-center">
                  <.icon name="hero-key" class="size-8 text-accent" />
                </div>

                <div>
                  <div class="flex items-center space-x-3 mb-2">
                    <h2 class="text-2xl font-bold">{@permission.action}</h2>
                    <div class="badge badge-accent badge-lg">{@permission.resource}</div>
                  </div>

                  <%= if @permission.description do %>
                    <p class="text-base-content/70 text-lg mb-4">{@permission.description}</p>
                  <% else %>
                    <p class="text-base-content/50 text-sm mb-4 italic">No description provided</p>
                  <% end %>

                  <div class="text-sm text-base-content/50">
                    Created {Calendar.strftime(@permission.inserted_at, "%B %d, %Y")}
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
                    <.link
                      patch={~p"/admin/permissions/#{@permission}/show/edit"}
                      class="btn btn-ghost btn-sm"
                    >
                      <.icon name="hero-pencil" class="size-4" /> Edit Permission
                    </.link>
                  </li>
                  <li>
                    <button
                      phx-click="delete"
                      phx-value-id={@permission.id}
                      data-confirm="Are you sure you want to delete this permission? This action cannot be undone."
                      class="btn btn-ghost btn-sm text-error hover:bg-error/10"
                    >
                      <.icon name="hero-trash" class="size-4" /> Delete Permission
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
            title="Assigned Roles"
            value={to_string(@stats.role_count)}
            icon="hero-user-group"
            color="secondary"
            description="roles with this permission"
          />

          <.stat_card
            title="Effective Users"
            value={to_string(@stats.user_count)}
            icon="hero-users"
            color="primary"
            description="users with access"
          />

          <.stat_card
            title="Created"
            value={Calendar.strftime(@permission.inserted_at, "%b %d")}
            icon="hero-calendar-days"
            color="info"
            description={to_string(Date.diff(Date.utc_today(), Date.from_iso8601!(Calendar.strftime(@permission.inserted_at, "%Y-%m-%d")))) <> " days ago"}
          />
        </div>
        
    <!-- Details Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- Assigned Roles Card -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex items-center justify-between mb-4">
                <h3 class="card-title">Assigned to Roles</h3>
                <div class="badge badge-secondary">{length(@assigned_roles)}</div>
              </div>

              <%= if @assigned_roles == [] do %>
                <div class="text-center py-8 text-base-content/50">
                  <.icon name="hero-user-group" class="size-12 mx-auto mb-2" />
                  <p>Not assigned to any roles</p>
                  <p class="text-sm mt-1">Assign this permission through role management</p>
                </div>
              <% else %>
                <div class="space-y-3 max-h-96 overflow-y-auto">
                  <div
                    :for={role <- @assigned_roles}
                    class="flex items-center justify-between p-3 bg-base-200 rounded-lg"
                  >
                    <div class="flex items-center space-x-3">
                      <div class="w-3 h-3 bg-secondary rounded-full"></div>
                      <div>
                        <div class="font-medium">{role.name}</div>
                        <%= if role.description do %>
                          <div class="text-sm text-base-content/70 truncate max-w-48">
                            {role.description}
                          </div>
                        <% end %>
                      </div>
                    </div>

                    <div class="flex items-center space-x-2">
                      <.link navigate={~p"/admin/roles/#{role}"} class="btn btn-ghost btn-xs">
                        <.icon name="hero-eye" class="size-3" />
                      </.link>
                      <button
                        phx-click="remove_role"
                        phx-value-role_id={role.id}
                        data-confirm="Remove this permission from the role?"
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
          
    <!-- Effective Users Card -->
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex items-center justify-between mb-4">
                <h3 class="card-title">Users with Access</h3>
                <div class="badge badge-primary">{length(@effective_users)}</div>
              </div>

              <%= if @effective_users == [] do %>
                <div class="text-center py-8 text-base-content/50">
                  <.icon name="hero-users" class="size-12 mx-auto mb-2" />
                  <p>No users have this permission</p>
                  <p class="text-sm mt-1">Users get permissions through assigned roles</p>
                </div>
              <% else %>
                <div class="space-y-3 max-h-96 overflow-y-auto">
                  <div
                    :for={user <- @effective_users}
                    class="flex items-center justify-between p-2 bg-base-200 rounded"
                  >
                    <div class="flex items-center space-x-3">
                      <div class="avatar placeholder">
                        <div class="w-6 h-6 bg-primary text-primary-content rounded-full">
                          <span class="text-xs font-semibold">
                            {String.first(user.name || user.email) |> String.upcase()}
                          </span>
                        </div>
                      </div>
                      <div>
                        <div class="text-sm font-medium">{user.name || "No name"}</div>
                        <div class="text-xs text-base-content/70">{user.email}</div>
                      </div>
                    </div>

                    <.link navigate={~p"/admin/users/#{user}"} class="btn btn-ghost btn-xs">
                      <.icon name="hero-eye" class="size-3" />
                    </.link>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        </div>
        
    <!-- Related Permissions -->
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h3 class="card-title mb-4">Related Permissions</h3>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <!-- Same Resource -->
              <div>
                <h4 class="font-semibold text-sm text-base-content/80 mb-2">
                  Same Resource ({@permission.resource})
                </h4>
                <div class="space-y-2">
                  <%= for related <- get_related_permissions_by_resource(@permission) do %>
                    <.link
                      navigate={~p"/admin/permissions/#{related}"}
                      class="flex items-center space-x-2 p-2 bg-base-200 rounded hover:bg-base-300 transition-colors"
                    >
                      <div class="w-2 h-2 bg-accent rounded-full"></div>
                      <span class="text-sm">{related.action}</span>
                    </.link>
                  <% end %>
                </div>
              </div>
              
    <!-- Same Action -->
              <div>
                <h4 class="font-semibold text-sm text-base-content/80 mb-2">
                  Same Action ({@permission.action})
                </h4>
                <div class="space-y-2">
                  <%= for related <- get_related_permissions_by_action(@permission) do %>
                    <.link
                      navigate={~p"/admin/permissions/#{related}"}
                      class="flex items-center space-x-2 p-2 bg-base-200 rounded hover:bg-base-300 transition-colors"
                    >
                      <div class="w-2 h-2 bg-accent rounded-full"></div>
                      <span class="text-sm">{related.resource}</span>
                    </.link>
                  <% end %>
                </div>
              </div>
            </div>
          </div>
        </div>
        
    <!-- Edit Permission Modal -->
        <.modal
          :if={@live_action == :edit}
          id="edit-permission-modal"
          show
          on_cancel={JS.patch(~p"/admin/permissions/#{@permission}")}
        >
          <:header>Edit Permission</:header>
          <:body>
            <.live_component
              module={BaseAclExWeb.Admin.PermissionLive.FormComponent}
              id={@permission.id}
              title="Edit Permission"
              action={:edit}
              permission={@permission}
              patch={~p"/admin/permissions/#{@permission}"}
            />
          </:body>
        </.modal>
      </div>
    </Layouts.admin>
    """
  end

  defp get_permission!(id) do
    Repo.get!(Permission, id)
  end

  defp get_permission_roles(permission_id) do
    from(r in Role,
      join: rp in "role_permissions",
      on: rp.role_id == r.id,
      where: rp.permission_id == ^permission_id,
      order_by: r.name
    )
    |> Repo.all()
  end

  defp get_users_with_permission(permission_id) do
    from(u in User,
      join: ur in "user_roles",
      on: ur.user_id == u.id,
      join: rp in "role_permissions",
      on: rp.role_id == ur.role_id,
      where: rp.permission_id == ^permission_id,
      distinct: true,
      order_by: [u.name, u.email]
    )
    |> Repo.all()
  end

  defp get_permission_stats(permission_id) do
    %{
      role_count: get_permission_role_count(permission_id),
      user_count: get_permission_user_count(permission_id)
    }
  end

  defp get_permission_role_count(permission_id) do
    from(rp in "role_permissions", where: rp.permission_id == ^permission_id)
    |> Repo.aggregate(:count, :role_id)
  end

  defp get_permission_user_count(permission_id) do
    from(u in User,
      join: ur in "user_roles",
      on: ur.user_id == u.id,
      join: rp in "role_permissions",
      on: rp.role_id == ur.role_id,
      where: rp.permission_id == ^permission_id,
      distinct: true
    )
    |> Repo.aggregate(:count, :id)
  end

  defp delete_permission(permission) do
    role_count = get_permission_role_count(permission.id)

    if role_count > 0 do
      {:error, :has_roles}
    else
      Repo.delete(permission)
    end
  end

  defp remove_permission_from_role(permission_id, role_id) do
    from(rp in "role_permissions",
      where: rp.permission_id == ^permission_id and rp.role_id == ^role_id
    )
    |> Repo.delete_all()
    |> case do
      {1, _} -> {:ok, :removed}
      _ -> {:error, :not_found}
    end
  end

  defp get_related_permissions_by_resource(permission) do
    from(p in Permission,
      where: p.resource == ^permission.resource and p.id != ^permission.id,
      order_by: p.action,
      limit: 5
    )
    |> Repo.all()
  end

  defp get_related_permissions_by_action(permission) do
    from(p in Permission,
      where: p.action == ^permission.action and p.id != ^permission.id,
      order_by: p.resource,
      limit: 5
    )
    |> Repo.all()
  end
end
