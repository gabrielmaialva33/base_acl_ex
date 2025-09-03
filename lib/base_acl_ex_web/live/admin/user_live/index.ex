defmodule BaseAclExWeb.Admin.UserLive.Index do
  use BaseAclExWeb, :live_view

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.Repo
  import Ecto.Query
  import BaseAclExWeb.AdminComponents

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Users")
      |> assign(:users, list_users())
      |> assign(:search_term, "")
      |> assign(:selected_role, "")
      |> assign(:roles, list_roles())

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :edit, %{"id" => id}) do
    socket
    |> assign(:page_title, "Edit User")
    |> assign(:user, get_user!(id))
  end

  defp apply_action(socket, :new, _params) do
    socket
    |> assign(:page_title, "New User")
    |> assign(:user, %User{})
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Users")
    |> assign(:user, nil)
  end

  @impl true
  def handle_event("search", %{"search" => search_term}, socket) do
    users = search_users(search_term, socket.assigns.selected_role)

    socket =
      socket
      |> assign(:search_term, search_term)
      |> assign(:users, users)

    {:noreply, socket}
  end

  def handle_event("filter_role", %{"role" => role}, socket) do
    users = search_users(socket.assigns.search_term, role)

    socket =
      socket
      |> assign(:selected_role, role)
      |> assign(:users, users)

    {:noreply, socket}
  end

  def handle_event("delete", %{"id" => id}, socket) do
    user = get_user!(id)

    case Repo.delete(user) do
      {:ok, _user} ->
        socket =
          socket
          |> put_flash(:info, "User deleted successfully")
          |> assign(:users, list_users())

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
          <:title>Users</:title>
          <:description>Manage system users and their permissions</:description>
          <:action>
            <.link patch={~p"/admin/users/new"} class="btn btn-primary">
              <.icon name="hero-plus" class="size-4" /> Add User
            </.link>
          </:action>
        </.page_header>
        
    <!-- Search and Filters -->
        <.search_form
          id="user-search"
          placeholder="Search users..."
          on_search="search"
          value={@search_term}
        >
          <:filter>
            <select class="select select-bordered" phx-change="filter_role">
              <option value="">All Roles</option>
              <option :for={role <- @roles} value={role.name} selected={@selected_role == role.name}>
                {role.name}
              </option>
            </select>
          </:filter>
        </.search_form>
        
    <!-- Users Data Table -->
        <.data_table id="users-table" rows={@users} row_id={fn user -> "user-#{user.id}" end}>
          <:col :let={user} label="Name" sortable>
            <div class="flex items-center space-x-3">
              <div class="avatar placeholder">
                <div class="w-8 h-8 bg-primary text-primary-content rounded-full">
                  <span class="text-xs font-semibold">
                    {String.first(user.name || user.email) |> String.upcase()}
                  </span>
                </div>
              </div>
              <div>
                <div class="font-semibold">{user.name || "No name"}</div>
                <div class="text-sm text-base-content/70">{user.email}</div>
              </div>
            </div>
          </:col>

          <:col :let={_user} label="Status" sortable>
            <div class="badge badge-success gap-2">
              <div class="w-2 h-2 bg-success rounded-full"></div>
              Active
            </div>
          </:col>

          <:col :let={user} label="Created" sortable>
            <%= if user.inserted_at do %>
              <time class="text-sm">
                {Calendar.strftime(user.inserted_at, "%Y-%m-%d")}
              </time>
            <% else %>
              <span class="text-sm text-base-content/50">Unknown</span>
            <% end %>
          </:col>

          <:action :let={user}>
            <.link patch={~p"/admin/users/#{user}/edit"} class="btn btn-ghost btn-xs">
              <.icon name="hero-pencil" class="size-3" /> Edit
            </.link>

            <.link navigate={~p"/admin/users/#{user}"} class="btn btn-ghost btn-xs">
              <.icon name="hero-eye" class="size-3" /> View
            </.link>

            <button
              phx-click="delete"
              phx-value-id={user.id}
              data-confirm="Are you sure you want to delete this user?"
              class="btn btn-ghost btn-xs text-error hover:bg-error/10"
            >
              <.icon name="hero-trash" class="size-3" /> Delete
            </button>
          </:action>
        </.data_table>
        
    <!-- User Form Modal -->
        <.modal
          :if={@live_action in [:new, :edit]}
          id="user-modal"
          show
          on_cancel={JS.patch(~p"/admin/users")}
        >
          <:header>{@page_title}</:header>
          <:body>
            <.live_component
              module={BaseAclExWeb.Admin.UserLive.FormComponent}
              id={@user.id || :new}
              title={@page_title}
              action={@live_action}
              user={@user}
              patch={~p"/admin/users"}
            />
          </:body>
        </.modal>
      </div>
    </Layouts.admin>
    """
  end

  defp list_users do
    from(u in User, order_by: [desc: u.inserted_at])
    |> Repo.all()
  end

  defp list_roles do
    from(r in Role, order_by: r.name)
    |> Repo.all()
  end

  defp search_users(search_term, role_filter) do
    query = from(u in User)

    query =
      if search_term != "" do
        search_pattern = "%#{search_term}%"

        from(u in query,
          where: ilike(u.name, ^search_pattern) or ilike(u.email, ^search_pattern)
        )
      else
        query
      end

    query =
      if role_filter != "" do
        from(u in query,
          join: ur in "user_roles",
          on: ur.user_id == u.id,
          join: r in Role,
          on: r.id == ur.role_id,
          where: r.name == ^role_filter
        )
      else
        query
      end

    from(u in query, order_by: [desc: u.inserted_at])
    |> Repo.all()
  end

  defp get_user!(id) do
    Repo.get!(User, id)
  end
end
