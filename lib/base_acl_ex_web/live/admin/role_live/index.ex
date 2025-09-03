defmodule BaseAclExWeb.Admin.RoleLive.Index do
  use BaseAclExWeb, :live_view

  alias BaseAclEx.Identity.Core.Entities.{Permission, Role}
  alias BaseAclEx.Repo
  import Ecto.Query
  import BaseAclExWeb.AdminComponents

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Roles")
      |> assign(:roles, list_roles())
      |> assign(:search_term, "")

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :edit, %{"id" => id}) do
    socket
    |> assign(:page_title, "Edit Role")
    |> assign(:role, get_role!(id))
  end

  defp apply_action(socket, :new, _params) do
    socket
    |> assign(:page_title, "New Role")
    |> assign(:role, %Role{})
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Roles")
    |> assign(:role, nil)
  end

  @impl true
  def handle_event("search", %{"search" => search_term}, socket) do
    roles = search_roles(search_term)

    socket =
      socket
      |> assign(:search_term, search_term)
      |> assign(:roles, roles)

    {:noreply, socket}
  end

  def handle_event("delete", %{"id" => id}, socket) do
    role = get_role!(id)

    case delete_role(role) do
      {:ok, _role} ->
        socket =
          socket
          |> put_flash(:info, "Role deleted successfully")
          |> assign(:roles, list_roles())

        {:noreply, socket}

      {:error, :has_users} ->
        {:noreply, put_flash(socket, :error, "Cannot delete role that has assigned users")}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to delete role")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.admin flash={@flash} current_user={@current_user}>
      <div class="space-y-6">
        <!-- Page Header -->
        <.page_header>
          <:title>Roles</:title>
          <:description>Manage user roles and their permissions</:description>
          <:action>
            <.link patch={~p"/admin/roles/new"} class="btn btn-primary">
              <.icon name="hero-plus" class="size-4" /> Create Role
            </.link>
          </:action>
        </.page_header>
        
    <!-- Search -->
        <.search_form
          id="role-search"
          placeholder="Search roles..."
          on_search="search"
          value={@search_term}
        />
        
    <!-- Roles Data Table -->
        <.data_table id="roles-table" rows={@roles} row_id={fn role -> "role-#{role.id}" end}>
          <:col :let={role} label="Role Name" sortable>
            <div class="flex items-center space-x-3">
              <div class="w-3 h-3 bg-secondary rounded-full"></div>
              <div>
                <div class="font-semibold text-lg">{role.name}</div>
                <%= if role.description do %>
                  <div class="text-sm text-base-content/70 line-clamp-2">
                    {role.description}
                  </div>
                <% end %>
              </div>
            </div>
          </:col>

          <:col :let={role} label="Users" sortable>
            <div class="flex items-center space-x-2">
              <.icon name="hero-users" class="size-4 text-base-content/50" />
              <span class="font-medium">{get_role_user_count(role.id)}</span>
              <span class="text-sm text-base-content/70">users</span>
            </div>
          </:col>

          <:col :let={role} label="Permissions" sortable>
            <div class="flex items-center space-x-2">
              <.icon name="hero-key" class="size-4 text-base-content/50" />
              <span class="font-medium">{get_role_permission_count(role.id)}</span>
              <span class="text-sm text-base-content/70">permissions</span>
            </div>
          </:col>

          <:col :let={role} label="Created" sortable>
            <%= if role.inserted_at do %>
              <time class="text-sm">
                {Calendar.strftime(role.inserted_at, "%Y-%m-%d")}
              </time>
            <% else %>
              <span class="text-sm text-base-content/50">Unknown</span>
            <% end %>
          </:col>

          <:action :let={role}>
            <.link patch={~p"/admin/roles/#{role}/edit"} class="btn btn-ghost btn-xs">
              <.icon name="hero-pencil" class="size-3" /> Edit
            </.link>

            <.link navigate={~p"/admin/roles/#{role}"} class="btn btn-ghost btn-xs">
              <.icon name="hero-eye" class="size-3" /> View
            </.link>

            <button
              phx-click="delete"
              phx-value-id={role.id}
              data-confirm="Are you sure you want to delete this role?"
              class="btn btn-ghost btn-xs text-error hover:bg-error/10"
            >
              <.icon name="hero-trash" class="size-3" /> Delete
            </button>
          </:action>
        </.data_table>
        
    <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <.stat_card
            title="Total Roles"
            value={to_string(length(@roles))}
            icon="hero-user-group"
            color="secondary"
            description="system roles"
          />

          <.stat_card
            title="Active Users"
            value={to_string(get_total_users_with_roles())}
            icon="hero-users"
            color="primary"
            description="with assigned roles"
          />

          <.stat_card
            title="Available Permissions"
            value={to_string(get_total_permissions())}
            icon="hero-key"
            color="accent"
            description="system permissions"
          />
        </div>
        
    <!-- Role Form Modal -->
        <.modal
          :if={@live_action in [:new, :edit]}
          id="role-modal"
          show
          on_cancel={JS.patch(~p"/admin/roles")}
        >
          <:header>{@page_title}</:header>
          <:body>
            <.live_component
              module={BaseAclExWeb.Admin.RoleLive.FormComponent}
              id={@role.id || :new}
              title={@page_title}
              action={@live_action}
              role={@role}
              patch={~p"/admin/roles"}
            />
          </:body>
        </.modal>
      </div>
    </Layouts.admin>
    """
  end

  defp list_roles do
    from(r in Role, order_by: [desc: r.inserted_at])
    |> Repo.all()
  end

  defp search_roles(search_term) do
    if search_term == "" do
      list_roles()
    else
      search_pattern = "%#{search_term}%"

      from(r in Role,
        where: ilike(r.name, ^search_pattern) or ilike(r.description, ^search_pattern),
        order_by: [desc: r.inserted_at]
      )
      |> Repo.all()
    end
  end

  defp get_role!(id) do
    Repo.get!(Role, id)
  end

  defp delete_role(role) do
    # Check if role has assigned users
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

  defp get_role_user_count(role_id) do
    from(ur in "user_roles", where: ur.role_id == ^role_id)
    |> Repo.aggregate(:count, :role_id)
  end

  defp get_role_permission_count(role_id) do
    from(rp in "role_permissions", where: rp.role_id == ^role_id)
    |> Repo.aggregate(:count, :permission_id)
  end

  defp get_total_users_with_roles do
    from(ur in "user_roles", distinct: ur.user_id)
    |> Repo.aggregate(:count, :user_id)
  end

  defp get_total_permissions do
    Repo.aggregate(Permission, :count, :id)
  end
end
