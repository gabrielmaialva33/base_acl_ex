defmodule BaseAclExWeb.Admin.PermissionLive.FormComponent do
  use BaseAclExWeb, :live_component

  alias BaseAclEx.Repo
  alias BaseAclEx.Identity.Core.Entities.{Permission, Role}
  import Ecto.Query
  import Ecto.Changeset

  @common_actions ~w[
    create read update delete
    list show edit
    admin manage
    view access
    publish unpublish
    approve reject
    export import
  ]

  @common_resources ~w[
    user users
    role roles
    permission permissions
    system admin
    dashboard analytics
    profile settings
    content posts
    files uploads
    reports audit
  ]

  @impl true
  def render(assigns) do
    ~H"""
    <div>
      <.form
        for={@form}
        id="permission-form"
        phx-target={@myself}
        phx-change="validate"
        phx-submit="save"
      >
        <!-- Action Field with Suggestions -->
        <div class="form-control">
          <label class="label">
            <span class="label-text font-semibold">Action</span>
            <span class="label-text-alt text-xs text-base-content/50">What can be done?</span>
          </label>

          <.input field={@form[:action]} type="text" placeholder="e.g., create, read, update, delete" />
          
    <!-- Action Suggestions -->
          <div class="mt-2">
            <div class="text-xs text-base-content/50 mb-1">Common actions:</div>
            <div class="flex flex-wrap gap-1">
              <button
                :for={action <- @common_actions}
                type="button"
                class="badge badge-outline badge-sm hover:badge-primary cursor-pointer"
                phx-target={@myself}
                phx-click="select_action"
                phx-value-action={action}
              >
                {action}
              </button>
            </div>
          </div>
        </div>
        
    <!-- Resource Field with Suggestions -->
        <div class="form-control">
          <label class="label">
            <span class="label-text font-semibold">Resource</span>
            <span class="label-text-alt text-xs text-base-content/50">What is being acted upon?</span>
          </label>

          <.input field={@form[:resource]} type="text" placeholder="e.g., users, posts, system" />
          
    <!-- Resource Suggestions -->
          <div class="mt-2">
            <div class="text-xs text-base-content/50 mb-1">Common resources:</div>
            <div class="flex flex-wrap gap-1">
              <button
                :for={resource <- @common_resources}
                type="button"
                class="badge badge-outline badge-sm hover:badge-secondary cursor-pointer"
                phx-target={@myself}
                phx-click="select_resource"
                phx-value-resource={resource}
              >
                {resource}
              </button>
            </div>
          </div>
        </div>
        
    <!-- Description Field -->
        <.input
          field={@form[:description]}
          type="textarea"
          label="Description"
          placeholder="Describe what this permission allows users to do..."
          rows="3"
        />
        
    <!-- Existing Permissions Preview -->
        <%= if @existing_permissions != [] do %>
          <div class="form-control">
            <label class="label">
              <span class="label-text font-semibold">Related Permissions</span>
            </label>

            <div class="bg-base-200 rounded-lg p-3 max-h-32 overflow-y-auto">
              <div class="text-xs text-base-content/70 mb-2">
                Existing permissions with similar action or resource:
              </div>
              <div class="space-y-1">
                <div :for={perm <- @existing_permissions} class="flex items-center space-x-2 text-sm">
                  <div class="w-1.5 h-1.5 bg-base-content/30 rounded-full"></div>
                  <span class="font-medium">{perm.action}</span>
                  <span class="text-base-content/50">•</span>
                  <span class="text-base-content/70">{perm.resource}</span>
                </div>
              </div>
            </div>
          </div>
        <% end %>
        
    <!-- Role Assignment (for new permissions) -->
        <%= if @action == :new and @roles != [] do %>
          <div class="form-control">
            <label class="label">
              <span class="label-text font-semibold">Assign to Roles</span>
              <span class="label-text-alt text-xs text-base-content/50">
                Optional: Assign this permission to roles immediately
              </span>
            </label>

            <div class="space-y-2 max-h-40 overflow-y-auto border border-base-300 rounded-lg p-3">
              <label :for={role <- @roles} class="label cursor-pointer justify-start space-x-3">
                <input
                  type="checkbox"
                  name="permission[role_ids][]"
                  value={role.id}
                  class="checkbox checkbox-secondary checkbox-sm"
                />
                <div class="flex-1">
                  <span class="label-text font-medium">{role.name}</span>
                  <%= if role.description do %>
                    <div class="text-xs text-base-content/70">{role.description}</div>
                  <% end %>
                </div>
              </label>
            </div>
          </div>
        <% end %>

        <div class="flex justify-end space-x-2 mt-6">
          <button type="button" phx-click="cancel" phx-target={@myself} class="btn btn-ghost">
            Cancel
          </button>
          <.button type="submit" phx-disable-with="Saving..." class="btn btn-primary">
            {if @action == :new, do: "Create Permission", else: "Update Permission"}
          </.button>
        </div>
      </.form>
    </div>
    """
  end

  @impl true
  def update(%{permission: permission} = assigns, socket) do
    roles = list_roles()
    existing_permissions = get_related_permissions(permission)

    socket =
      socket
      |> assign(assigns)
      |> assign(:roles, roles)
      |> assign(:existing_permissions, existing_permissions)
      |> assign(:common_actions, @common_actions)
      |> assign(:common_resources, @common_resources)
      |> assign_new(:form, fn ->
        to_form(permission_changeset(permission))
      end)

    {:ok, socket}
  end

  @impl true
  def handle_event("validate", %{"permission" => permission_params}, socket) do
    changeset = permission_changeset(socket.assigns.permission, permission_params)
    existing_permissions = get_related_permissions_from_params(permission_params)

    socket =
      socket
      |> assign(form: to_form(changeset, action: :validate))
      |> assign(:existing_permissions, existing_permissions)

    {:noreply, socket}
  end

  def handle_event("save", %{"permission" => permission_params}, socket) do
    save_permission(socket, socket.assigns.action, permission_params)
  end

  def handle_event("cancel", _params, socket) do
    {:noreply, push_patch(socket, to: socket.assigns.patch)}
  end

  def handle_event("select_action", %{"action" => action}, socket) do
    current_params = form_to_params(socket.assigns.form)
    updated_params = Map.put(current_params, "action", action)

    changeset = permission_changeset(socket.assigns.permission, updated_params)
    existing_permissions = get_related_permissions_from_params(updated_params)

    socket =
      socket
      |> assign(form: to_form(changeset, action: :validate))
      |> assign(:existing_permissions, existing_permissions)

    {:noreply, socket}
  end

  def handle_event("select_resource", %{"resource" => resource}, socket) do
    current_params = form_to_params(socket.assigns.form)
    updated_params = Map.put(current_params, "resource", resource)

    changeset = permission_changeset(socket.assigns.permission, updated_params)
    existing_permissions = get_related_permissions_from_params(updated_params)

    socket =
      socket
      |> assign(form: to_form(changeset, action: :validate))
      |> assign(:existing_permissions, existing_permissions)

    {:noreply, socket}
  end

  defp save_permission(socket, :edit, permission_params) do
    case update_permission(socket.assigns.permission, permission_params) do
      {:ok, permission} ->
        notify_parent({:saved, permission})

        socket =
          socket
          |> put_flash(:info, "Permission updated successfully")
          |> push_patch(to: socket.assigns.patch)

        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  defp save_permission(socket, :new, permission_params) do
    case create_permission(permission_params) do
      {:ok, permission} ->
        notify_parent({:saved, permission})

        socket =
          socket
          |> put_flash(:info, "Permission created successfully")
          |> push_patch(to: socket.assigns.patch)

        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  defp create_permission(attrs) do
    changeset = permission_changeset(%Permission{}, attrs)

    Repo.transaction(fn ->
      case Repo.insert(changeset) do
        {:ok, permission} ->
          # Assign to roles if provided
          role_ids = extract_role_ids(attrs)
          assign_permission_to_roles(permission, role_ids)
          permission

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  defp update_permission(permission, attrs) do
    changeset = permission_changeset(permission, attrs)
    Repo.update(changeset)
  end

  defp permission_changeset(permission, attrs \\ %{}) do
    permission
    |> cast(attrs, [:action, :resource, :description])
    |> validate_required([:action, :resource])
    |> validate_length(:action, min: 2, max: 50)
    |> validate_length(:resource, min: 2, max: 50)
    |> validate_length(:description, max: 255)
    |> validate_format(:action, ~r/^[a-z_]+$/,
      message: "must be lowercase letters and underscores only"
    )
    |> validate_format(:resource, ~r/^[a-z_]+$/,
      message: "must be lowercase letters and underscores only"
    )
    |> unique_constraint([:action, :resource],
      message: "permission already exists for this action and resource"
    )
  end

  defp extract_role_ids(attrs) do
    case attrs["role_ids"] do
      role_ids when is_list(role_ids) ->
        Enum.map(role_ids, &String.to_integer/1)

      _ ->
        []
    end
  end

  defp assign_permission_to_roles(permission, role_ids) do
    role_permissions =
      Enum.map(role_ids, fn role_id ->
        %{
          role_id: role_id,
          permission_id: permission.id,
          inserted_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
          updated_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
        }
      end)

    if role_permissions != [] do
      Repo.insert_all("role_permissions", role_permissions)
    end
  end

  defp list_roles do
    from(r in Role, order_by: r.name)
    |> Repo.all()
  end

  defp get_related_permissions(permission) do
    if permission.id do
      # For existing permissions, we don't show related ones in the form
      []
    else
      # Will be populated during validation
      []
    end
  end

  defp get_related_permissions_from_params(params) do
    action = params["action"]
    resource = params["resource"]

    cond do
      is_nil(action) or action == "" ->
        []

      is_nil(resource) or resource == "" ->
        []

      true ->
        from(p in Permission,
          where:
            (p.action == ^action and p.resource != ^resource) or
              (p.resource == ^resource and p.action != ^action),
          order_by: [p.resource, p.action],
          limit: 10
        )
        |> Repo.all()
    end
  end

  defp form_to_params(form) do
    form.params || %{}
  end

  defp notify_parent(msg), do: send(self(), {__MODULE__, msg})
end
