defmodule BaseAclExWeb.Admin.PermissionLive.Index do
  use BaseAclExWeb, :live_view

  alias BaseAclEx.Identity.Core.Entities.Permission
  alias BaseAclEx.Repo
  import Ecto.Query
  import BaseAclExWeb.AdminComponents

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Permissions")
      |> assign(:permissions, list_permissions())
      |> assign(:search_term, "")
      |> assign(:selected_resource, "")
      |> assign(:resources, get_available_resources())

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :edit, %{"id" => id}) do
    socket
    |> assign(:page_title, "Edit Permission")
    |> assign(:permission, get_permission!(id))
  end

  defp apply_action(socket, :new, _params) do
    socket
    |> assign(:page_title, "New Permission")
    |> assign(:permission, %Permission{})
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Permissions")
    |> assign(:permission, nil)
  end

  @impl true
  def handle_event("search", %{"search" => search_term}, socket) do
    permissions = search_permissions(search_term, socket.assigns.selected_resource)

    socket =
      socket
      |> assign(:search_term, search_term)
      |> assign(:permissions, permissions)

    {:noreply, socket}
  end

  def handle_event("filter_resource", %{"resource" => resource}, socket) do
    permissions = search_permissions(socket.assigns.search_term, resource)

    socket =
      socket
      |> assign(:selected_resource, resource)
      |> assign(:permissions, permissions)

    {:noreply, socket}
  end

  def handle_event("delete", %{"id" => id}, socket) do
    permission = get_permission!(id)

    case delete_permission(permission) do
      {:ok, _permission} ->
        socket =
          socket
          |> put_flash(:info, "Permission deleted successfully")
          |> assign(:permissions, list_permissions())
          |> assign(:resources, get_available_resources())

        {:noreply, socket}

      {:error, :has_roles} ->
        {:noreply,
         put_flash(socket, :error, "Cannot delete permission that is assigned to roles")}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to delete permission")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.admin flash={@flash} current_user={@current_user}>
      <div class="space-y-6">
        <!-- Page Header -->
        <.page_header>
          <:title>Permissions</:title>
          <:description>Manage system permissions and access controls</:description>
          <:action>
            <.link patch={~p"/admin/permissions/new"} class="btn btn-primary">
              <.icon name="hero-plus" class="size-4" /> Create Permission
            </.link>
          </:action>
        </.page_header>
        
    <!-- Search and Filters -->
        <.search_form
          id="permission-search"
          placeholder="Search permissions..."
          on_search="search"
          value={@search_term}
        >
          <:filter>
            <select class="select select-bordered" phx-change="filter_resource">
              <option value="">All Resources</option>
              <option
                :for={resource <- @resources}
                value={resource}
                selected={@selected_resource == resource}
              >
                {String.capitalize(resource)}
              </option>
            </select>
          </:filter>
        </.search_form>
        
    <!-- Permissions Data Table -->
        <.data_table
          id="permissions-table"
          rows={@permissions}
          row_id={fn permission -> "permission-#{permission.id}" end}
        >
          <:col :let={permission} label="Permission" sortable>
            <div class="flex items-center space-x-3">
              <div class="w-3 h-3 bg-accent rounded-full"></div>
              <div>
                <div class="font-semibold text-lg">
                  {permission.action}
                </div>
                <%= if permission.description do %>
                  <div class="text-sm text-base-content/70 line-clamp-2">
                    {permission.description}
                  </div>
                <% end %>
              </div>
            </div>
          </:col>

          <:col :let={permission} label="Resource" sortable>
            <div class="badge badge-outline badge-lg font-medium">
              {permission.resource}
            </div>
          </:col>

          <:col :let={permission} label="Roles" sortable>
            <div class="flex items-center space-x-2">
              <.icon name="hero-user-group" class="size-4 text-base-content/50" />
              <span class="font-medium">{get_permission_role_count(permission.id)}</span>
              <span class="text-sm text-base-content/70">roles</span>
            </div>
          </:col>

          <:col :let={permission} label="Created" sortable>
            <%= if permission.inserted_at do %>
              <time class="text-sm">
                {Calendar.strftime(permission.inserted_at, "%Y-%m-%d")}
              </time>
            <% else %>
              <span class="text-sm text-base-content/50">Unknown</span>
            <% end %>
          </:col>

          <:action :let={permission}>
            <.link patch={~p"/admin/permissions/#{permission}/edit"} class="btn btn-ghost btn-xs">
              <.icon name="hero-pencil" class="size-3" /> Edit
            </.link>

            <.link navigate={~p"/admin/permissions/#{permission}"} class="btn btn-ghost btn-xs">
              <.icon name="hero-eye" class="size-3" /> View
            </.link>

            <button
              phx-click="delete"
              phx-value-id={permission.id}
              data-confirm="Are you sure you want to delete this permission?"
              class="btn btn-ghost btn-xs text-error hover:bg-error/10"
            >
              <.icon name="hero-trash" class="size-3" /> Delete
            </button>
          </:action>
        </.data_table>
        
    <!-- Grouped Permissions Overview -->
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
          <%= for {resource, resource_permissions} <- group_permissions_by_resource(@permissions) do %>
            <div class="card bg-base-100 shadow">
              <div class="card-body">
                <div class="flex items-center justify-between mb-3">
                  <h3 class="card-title capitalize text-lg">{resource}</h3>
                  <div class="badge badge-accent">{length(resource_permissions)}</div>
                </div>

                <div class="space-y-2">
                  <div
                    :for={permission <- Enum.take(resource_permissions, 5)}
                    class="flex items-center space-x-2 text-sm"
                  >
                    <div class="w-2 h-2 bg-accent rounded-full"></div>
                    <span class="font-medium">{permission.action}</span>
                  </div>

                  <%= if length(resource_permissions) > 5 do %>
                    <div class="text-xs text-base-content/50 mt-2">
                      ...and {length(resource_permissions) - 5} more
                    </div>
                  <% end %>
                </div>
              </div>
            </div>
          <% end %>
        </div>
        
    <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
          <.stat_card
            title="Total Permissions"
            value={to_string(length(@permissions))}
            icon="hero-key"
            color="accent"
            description="system permissions"
          />

          <.stat_card
            title="Resources"
            value={to_string(length(@resources))}
            icon="hero-squares-2x2"
            color="primary"
            description="protected resources"
          />

          <.stat_card
            title="Active Roles"
            value={to_string(get_roles_with_permissions_count())}
            icon="hero-user-group"
            color="secondary"
            description="with permissions"
          />

          <.stat_card
            title="Most Common"
            value={get_most_common_action() || "None"}
            icon="hero-chart-bar"
            color="info"
            description="permission action"
          />
        </div>
        
    <!-- Permission Form Modal -->
        <.modal
          :if={@live_action in [:new, :edit]}
          id="permission-modal"
          show
          on_cancel={JS.patch(~p"/admin/permissions")}
        >
          <:header>{@page_title}</:header>
          <:body>
            <.live_component
              module={BaseAclExWeb.Admin.PermissionLive.FormComponent}
              id={@permission.id || :new}
              title={@page_title}
              action={@live_action}
              permission={@permission}
              patch={~p"/admin/permissions"}
            />
          </:body>
        </.modal>
      </div>
    </Layouts.admin>
    """
  end

  defp list_permissions do
    from(p in Permission, order_by: [p.resource, p.action])
    |> Repo.all()
  end

  defp search_permissions(search_term, resource_filter) do
    query = from(p in Permission)

    query =
      if search_term != "" do
        search_pattern = "%#{search_term}%"

        from(p in query,
          where:
            ilike(p.action, ^search_pattern) or
              ilike(p.resource, ^search_pattern) or
              ilike(p.description, ^search_pattern)
        )
      else
        query
      end

    query =
      if resource_filter != "" do
        from(p in query, where: p.resource == ^resource_filter)
      else
        query
      end

    from(p in query, order_by: [p.resource, p.action])
    |> Repo.all()
  end

  defp get_permission!(id) do
    Repo.get!(Permission, id)
  end

  defp delete_permission(permission) do
    # Check if permission is assigned to any roles
    role_count = get_permission_role_count(permission.id)

    if role_count > 0 do
      {:error, :has_roles}
    else
      Repo.delete(permission)
    end
  end

  defp get_permission_role_count(permission_id) do
    from(rp in "role_permissions", where: rp.permission_id == ^permission_id)
    |> Repo.aggregate(:count, :role_id)
  end

  defp get_available_resources do
    from(p in Permission,
      distinct: p.resource,
      select: p.resource,
      order_by: p.resource
    )
    |> Repo.all()
  end

  defp group_permissions_by_resource(permissions) do
    permissions
    |> Enum.group_by(& &1.resource)
    |> Enum.sort_by(fn {resource, _} -> resource end)
  end

  defp get_roles_with_permissions_count do
    from(rp in "role_permissions", distinct: rp.role_id)
    |> Repo.aggregate(:count, :role_id)
  end

  defp get_most_common_action do
    result =
      from(p in Permission,
        group_by: p.action,
        select: {p.action, count(p.id)},
        order_by: [desc: count(p.id)],
        limit: 1
      )
      |> Repo.one()

    case result do
      {action, _count} -> action
      nil -> nil
    end
  end
end
