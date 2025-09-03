defmodule BaseAclExWeb.Admin.RoleLive.FormComponent do
  use BaseAclExWeb, :live_component

  alias BaseAclEx.Identity.Core.Entities.{Permission, Role}
  alias BaseAclEx.Repo
  import Ecto.Query
  import Ecto.Changeset

  @impl true
  def render(assigns) do
    ~H"""
    <div>
      <.form
        for={@form}
        id="role-form"
        phx-target={@myself}
        phx-change="validate"
        phx-submit="save"
      >
        <.input
          field={@form[:name]}
          type="text"
          label="Role Name"
          placeholder="Enter role name (e.g., Admin, Manager)"
        />
        <.input
          field={@form[:description]}
          type="textarea"
          label="Description"
          placeholder="Describe the role and its responsibilities..."
          rows="3"
        />
        
    <!-- Permission Assignment -->
        <div class="form-control">
          <label class="label">
            <span class="label-text font-semibold">Assign Permissions</span>
            <span class="label-text-alt text-xs text-base-content/50">
              Select permissions this role should have
            </span>
          </label>

          <%= if @permissions == [] do %>
            <div class="alert alert-info">
              <.icon name="hero-information-circle" class="size-5" />
              <span>No permissions available. Create permissions first to assign them to roles.</span>
            </div>
          <% else %>
            <!-- Permission Search -->
            <div class="mb-3">
              <input
                type="text"
                placeholder="Search permissions..."
                class="input input-bordered input-sm w-full"
                phx-target={@myself}
                phx-keyup="search_permissions"
                phx-debounce="300"
              />
            </div>
            
    <!-- Grouped Permissions -->
            <div class="space-y-4 max-h-96 overflow-y-auto border border-base-300 rounded-lg p-4">
              <%= for {resource, permissions} <- @grouped_permissions do %>
                <div class="space-y-2">
                  <div class="flex items-center space-x-2">
                    <h4 class="font-semibold text-sm text-base-content/80 capitalize">
                      {resource}
                    </h4>
                    <div class="badge badge-ghost badge-xs">{length(permissions)}</div>
                  </div>

                  <div class="grid grid-cols-1 gap-2 ml-4">
                    <label
                      :for={permission <- permissions}
                      class="label cursor-pointer justify-start space-x-3"
                    >
                      <input
                        type="checkbox"
                        name="role[permission_ids][]"
                        value={permission.id}
                        checked={permission.id in (@selected_permission_ids || [])}
                        class="checkbox checkbox-secondary checkbox-sm"
                      />
                      <div class="flex-1">
                        <div class="flex items-center space-x-2">
                          <span class="label-text font-medium text-sm">{permission.action}</span>
                          <span class="badge badge-outline badge-xs">{permission.resource}</span>
                        </div>
                        <%= if permission.description do %>
                          <div class="text-xs text-base-content/60 mt-1">
                            {permission.description}
                          </div>
                        <% end %>
                      </div>
                    </label>
                  </div>
                </div>
              <% end %>
            </div>
          <% end %>
        </div>

        <div class="flex justify-end space-x-2 mt-6">
          <button type="button" phx-click="cancel" phx-target={@myself} class="btn btn-ghost">
            Cancel
          </button>
          <.button type="submit" phx-disable-with="Saving..." class="btn btn-primary">
            {if @action == :new, do: "Create Role", else: "Update Role"}
          </.button>
        </div>
      </.form>
    </div>
    """
  end

  @impl true
  def update(%{role: role} = assigns, socket) do
    permissions = list_permissions()
    grouped_permissions = group_permissions_by_resource(permissions)
    selected_permission_ids = get_role_permission_ids(role.id)

    socket =
      socket
      |> assign(assigns)
      |> assign(:permissions, permissions)
      |> assign(:grouped_permissions, grouped_permissions)
      |> assign(:selected_permission_ids, selected_permission_ids)
      |> assign(:permission_search, "")
      |> assign_new(:form, fn ->
        to_form(role_changeset(role))
      end)

    {:ok, socket}
  end

  @impl true
  def handle_event("validate", %{"role" => role_params}, socket) do
    changeset = role_changeset(socket.assigns.role, role_params)
    {:noreply, assign(socket, form: to_form(changeset, action: :validate))}
  end

  def handle_event("save", %{"role" => role_params}, socket) do
    save_role(socket, socket.assigns.action, role_params)
  end

  def handle_event("cancel", _params, socket) do
    {:noreply, push_patch(socket, to: socket.assigns.patch)}
  end

  def handle_event("search_permissions", %{"value" => search_term}, socket) do
    filtered_permissions = filter_permissions(socket.assigns.permissions, search_term)
    grouped_permissions = group_permissions_by_resource(filtered_permissions)

    socket =
      socket
      |> assign(:grouped_permissions, grouped_permissions)
      |> assign(:permission_search, search_term)

    {:noreply, socket}
  end

  defp save_role(socket, :edit, role_params) do
    case update_role(socket.assigns.role, role_params) do
      {:ok, role} ->
        notify_parent({:saved, role})

        socket =
          socket
          |> put_flash(:info, "Role updated successfully")
          |> push_patch(to: socket.assigns.patch)

        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  defp save_role(socket, :new, role_params) do
    case create_role(role_params) do
      {:ok, role} ->
        notify_parent({:saved, role})

        socket =
          socket
          |> put_flash(:info, "Role created successfully")
          |> push_patch(to: socket.assigns.patch)

        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  defp create_role(attrs) do
    changeset = role_changeset(%Role{}, attrs)

    Repo.transaction(fn ->
      case Repo.insert(changeset) do
        {:ok, role} ->
          # Assign permissions if provided
          permission_ids = extract_permission_ids(attrs)
          assign_permissions_to_role(role, permission_ids)
          role

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  defp update_role(role, attrs) do
    changeset = role_changeset(role, attrs)

    Repo.transaction(fn ->
      case Repo.update(changeset) do
        {:ok, updated_role} ->
          # Update permission assignments
          permission_ids = extract_permission_ids(attrs)
          update_role_permissions(updated_role, permission_ids)
          updated_role

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  defp role_changeset(role, attrs \\ %{}) do
    role
    |> cast(attrs, [:name, :description])
    |> validate_required([:name])
    |> validate_length(:name, min: 2, max: 50)
    |> validate_length(:description, max: 255)
    |> validate_format(:name, ~r/^[a-zA-Z0-9\s\-_]+$/,
      message: "can only contain letters, numbers, spaces, hyphens, and underscores"
    )
    |> unique_constraint(:name, message: "role name already exists")
  end

  defp extract_permission_ids(attrs) do
    case attrs["permission_ids"] do
      permission_ids when is_list(permission_ids) ->
        Enum.map(permission_ids, &String.to_integer/1)

      _ ->
        []
    end
  end

  defp assign_permissions_to_role(role, permission_ids) do
    # Remove existing permission assignments
    from(rp in "role_permissions", where: rp.role_id == ^role.id)
    |> Repo.delete_all()

    # Insert new permission assignments
    role_permissions =
      Enum.map(permission_ids, fn permission_id ->
        %{
          role_id: role.id,
          permission_id: permission_id,
          inserted_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
          updated_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
        }
      end)

    if role_permissions != [] do
      Repo.insert_all("role_permissions", role_permissions)
    end
  end

  defp update_role_permissions(role, permission_ids) do
    assign_permissions_to_role(role, permission_ids)
  end

  defp list_permissions do
    from(p in Permission, order_by: [p.resource, p.action])
    |> Repo.all()
  end

  defp filter_permissions(permissions, search_term) do
    if search_term == "" do
      permissions
    else
      search_lower = String.downcase(search_term)

      Enum.filter(permissions, fn permission ->
        String.contains?(String.downcase(permission.action), search_lower) ||
          String.contains?(String.downcase(permission.resource), search_lower) ||
          (permission.description &&
             String.contains?(String.downcase(permission.description), search_lower))
      end)
    end
  end

  defp group_permissions_by_resource(permissions) do
    permissions
    |> Enum.group_by(& &1.resource)
    |> Enum.sort_by(fn {resource, _} -> resource end)
  end

  defp get_role_permission_ids(nil), do: []

  defp get_role_permission_ids(role_id) do
    from(rp in "role_permissions",
      where: rp.role_id == ^role_id,
      select: rp.permission_id
    )
    |> Repo.all()
  end

  defp notify_parent(msg), do: send(self(), {__MODULE__, msg})
end
