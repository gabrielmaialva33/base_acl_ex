defmodule BaseAclExWeb.AdminComponents do
  @moduledoc """
  Reusable admin interface components for BaseAclEx admin dashboard.
  """
  use Phoenix.Component
  alias Phoenix.LiveView.JS
  import BaseAclExWeb.CoreComponents

  @doc """
  Renders a data table with sorting, filtering and pagination.

  ## Examples

      <.data_table id="users-table" rows={@users}>
        <:col :let={user} label="Name" sortable>
          <%= user.name %>
        </:col>
        <:col :let={user} label="Email" sortable>  
          <%= user.email %>
        </:col>
        <:action :let={user}>
          <.link navigate="/admin/users/edit">Edit</.link>
        </:action>
      </.data_table>

  """
  attr :id, :string, required: true
  attr :rows, :list, required: true
  attr :row_id, :any, default: nil, doc: "the function for generating the row id"
  attr :row_click, :any, default: nil, doc: "the function for handling phx-click on each row"

  attr :row_item, :any,
    default: &Function.identity/1,
    doc: "the function for mapping each row before calling the :col and :action slots"

  slot :col, required: true do
    attr :label, :string
    attr :sortable, :boolean
  end

  slot :action, doc: "the slot for showing user actions in the last table column"

  def data_table(assigns) do
    assigns =
      with %{rows: %Phoenix.LiveView.LiveStream{}} <- assigns do
        assign(assigns, row_id: assigns.row_id || fn {id, _item} -> id end)
      end

    ~H"""
    <div class="overflow-x-auto">
      <table class="table table-zebra w-full">
        <thead>
          <tr>
            <th :for={col <- @col} class="bg-base-200">
              <div class="flex items-center space-x-1">
                <span>{col[:label]}</span>
                <%= if col[:sortable] do %>
                  <button class="btn btn-ghost btn-xs">
                    <.icon name="hero-arrows-up-down" class="size-3" />
                  </button>
                <% end %>
              </div>
            </th>
            <th :if={@action != []} class="bg-base-200">
              <span class="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody
          id={@id}
          phx-update={(match?(%Phoenix.LiveView.LiveStream{}, @rows) && "stream") || "replace"}
        >
          <tr
            :for={row <- @rows}
            id={@row_id && @row_id.(row)}
            class="hover:bg-base-200 cursor-pointer"
            phx-click={@row_click && @row_click.(row)}
          >
            <td :for={col <- @col}>
              {render_slot(col, @row_item.(row))}
            </td>
            <td :if={@action != []}>
              <div class="flex items-center space-x-2">
                <%= for action <- @action do %>
                  {render_slot(action, @row_item.(row))}
                <% end %>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  @doc """
  Renders a page header with title, description and actions.

  ## Examples

      <.page_header>
        <:title>Users</:title>
        <:description>Manage system users and their permissions</:description>
        <:action>
          <.link patch={~p"/admin/users/new"} class="btn btn-primary">
            <.icon name="hero-plus" class="size-4" />
            Add User
          </.link>
        </:action>
      </.page_header>

  """
  slot :title, required: true
  slot :description
  slot :action

  def page_header(assigns) do
    ~H"""
    <div class="flex items-center justify-between pb-6 border-b border-base-300">
      <div>
        <h1 class="text-3xl font-bold text-base-content">
          {render_slot(@title)}
        </h1>
        <p :if={@description != []} class="text-base-content/70 mt-1">
          {render_slot(@description)}
        </p>
      </div>

      <div :if={@action != []} class="flex items-center space-x-2">
        <%= for action <- @action do %>
          {render_slot(action)}
        <% end %>
      </div>
    </div>
    """
  end

  @doc """
  Renders a stats card for displaying metrics.

  ## Examples

      <.stat_card 
        title="Total Users" 
        value="1,245" 
        icon="hero-users"
        trend={:up}
        change="+12%"
        description="vs last month"
      />

  """
  attr :title, :string, required: true
  attr :value, :string, required: true
  attr :icon, :string, required: true
  attr :trend, :atom, default: :neutral, values: [:up, :down, :neutral]
  attr :change, :string, default: nil
  attr :description, :string, default: nil

  attr :color, :string,
    default: "primary",
    values: ~w(primary secondary accent info success warning error)

  def stat_card(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
      <div class="card-body">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-base-content/70 text-sm font-medium">{@title}</p>
            <p class="text-3xl font-bold text-base-content">{@value}</p>
          </div>
          <div class={"w-12 h-12 bg-#{@color}/20 rounded-lg flex items-center justify-center"}>
            <.icon name={@icon} class={"size-6 text-#{@color}"} />
          </div>
        </div>

        <%= if @change do %>
          <div class="flex items-center mt-4 text-sm">
            <%= cond do %>
              <% @trend == :up -> %>
                <span class="text-success">{@change}</span>
              <% @trend == :down -> %>
                <span class="text-error">{@change}</span>
              <% true -> %>
                <span class="text-base-content/70">{@change}</span>
            <% end %>

            <span :if={@description} class="text-base-content/70 ml-1">{@description}</span>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  @doc """
  Renders a search input with optional filters.

  ## Examples

      <.search_form
        id="user-search"
        placeholder="Search users..."
        on_search="search"
        value={@search_term}
      >
        <:filter>
          <select class="select select-bordered">
            <option>All Roles</option>
            <option>Admin</option>
            <option>User</option>
          </select>
        </:filter>
      </.search_form>

  """
  attr :id, :string, required: true
  attr :placeholder, :string, default: "Search..."
  attr :value, :string, default: ""
  attr :on_search, :string, required: true

  slot :filter

  def search_form(assigns) do
    ~H"""
    <div class="flex items-center space-x-4 mb-6">
      <div class="flex-1 relative">
        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <.icon name="hero-magnifying-glass" class="size-4 text-base-content/50" />
        </div>
        <input
          type="text"
          id={@id}
          name="search"
          class="input input-bordered w-full pl-10"
          placeholder={@placeholder}
          value={@value}
          phx-change={@on_search}
          phx-debounce="300"
        />
      </div>

      <div :if={@filter != []} class="flex items-center space-x-2">
        <%= for filter <- @filter do %>
          {render_slot(filter)}
        <% end %>
      </div>
    </div>
    """
  end

  @doc """
  Renders a modal dialog with header and actions.

  ## Examples

      <.modal :if={@show_modal} id="user-modal" show on_cancel={JS.patch(~p"/admin/users")}>
        <:header>Add New User</:header>
        <:body>
          <!-- Modal content -->
        </:body>
        <:action>
          <button class="btn btn-primary">Save</button>
        </:action>
      </.modal>

  """
  attr :id, :string, required: true
  attr :show, :boolean, default: false
  attr :on_cancel, :any, default: %JS{}

  slot :header
  slot :body
  slot :action

  def modal(assigns) do
    ~H"""
    <div
      id={@id}
      phx-mounted={@show && show_modal(@id)}
      phx-remove={hide_modal(@id)}
      data-cancel={JS.exec(@on_cancel, "phx-remove")}
      class="relative z-50 hidden"
    >
      <div class="fixed inset-0 bg-black/50" aria-hidden="true"></div>
      <div class="fixed inset-0 overflow-y-auto">
        <div class="flex min-h-full items-center justify-center p-4">
          <div class="modal-box w-full max-w-2xl">
            <form method="dialog">
              <button
                phx-click={JS.exec("data-cancel", to: "##{@id}")}
                class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2"
              >
                <.icon name="hero-x-mark" class="size-4" />
              </button>
            </form>

            <h3 :if={@header != []} class="font-bold text-lg mb-4">
              {render_slot(@header)}
            </h3>

            <div :if={@body != []}>
              {render_slot(@body)}
            </div>

            <div :if={@action != []} class="modal-action">
              <%= for action <- @action do %>
                {render_slot(action)}
              <% end %>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp show_modal(js \\ %JS{}, id) do
    js
    |> JS.remove_class("hidden", to: "##{id}")
    |> JS.add_class("flex", to: "##{id}")
  end

  defp hide_modal(js \\ %JS{}, id) do
    js
    |> JS.add_class("hidden", to: "##{id}")
    |> JS.remove_class("flex", to: "##{id}")
  end
end
