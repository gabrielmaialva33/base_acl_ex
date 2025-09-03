defmodule BaseAclExWeb.Admin.UserLive.FormComponent do
  use BaseAclExWeb, :live_component

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.Repo
  import Ecto.Query
  import Ecto.Changeset

  @impl true
  def render(assigns) do
    ~H"""
    <div>
      <.form
        for={@form}
        id="user-form"
        phx-target={@myself}
        phx-change="validate"
        phx-submit="save"
      >
        <.input
          field={@form[:name]}
          type="text"
          label="Full Name"
          placeholder="Enter user's full name"
        />
        <.input
          field={@form[:email]}
          type="email"
          label="Email Address"
          placeholder="user@example.com"
        />

        <%= if @action == :new do %>
          <.input
            field={@form[:password]}
            type="password"
            label="Password"
            placeholder="Choose a secure password"
          />
          <.input
            field={@form[:password_confirmation]}
            type="password"
            label="Confirm Password"
            placeholder="Confirm the password"
          />
        <% end %>
        
    <!-- Role Assignment -->
        <div class="form-control">
          <label class="label">
            <span class="label-text font-semibold">Assign Roles</span>
          </label>

          <%= if @roles == [] do %>
            <div class="alert alert-info">
              <.icon name="hero-information-circle" class="size-5" />
              <span>No roles available. Create roles first to assign them to users.</span>
            </div>
          <% else %>
            <div class="space-y-2 max-h-40 overflow-y-auto border border-base-300 rounded-lg p-3">
              <label :for={role <- @roles} class="label cursor-pointer justify-start space-x-3">
                <input
                  type="checkbox"
                  name="user[role_ids][]"
                  value={role.id}
                  checked={role.id in (@selected_role_ids || [])}
                  class="checkbox checkbox-primary"
                />
                <div class="flex-1">
                  <span class="label-text font-medium">{role.name}</span>
                  <%= if role.description do %>
                    <div class="text-xs text-base-content/70">{role.description}</div>
                  <% end %>
                </div>
              </label>
            </div>
          <% end %>
        </div>

        <div class="flex justify-end space-x-2 mt-6">
          <button type="button" phx-click="cancel" phx-target={@myself} class="btn btn-ghost">
            Cancel
          </button>
          <.button type="submit" phx-disable-with="Saving..." class="btn btn-primary">
            {if @action == :new, do: "Create User", else: "Update User"}
          </.button>
        </div>
      </.form>
    </div>
    """
  end

  @impl true
  def update(%{user: user} = assigns, socket) do
    roles = list_roles()
    selected_role_ids = get_user_role_ids(user.id)

    socket =
      socket
      |> assign(assigns)
      |> assign(:roles, roles)
      |> assign(:selected_role_ids, selected_role_ids)
      |> assign_new(:form, fn ->
        to_form(user_changeset(user))
      end)

    {:ok, socket}
  end

  @impl true
  def handle_event("validate", %{"user" => user_params}, socket) do
    changeset = user_changeset(socket.assigns.user, user_params)
    {:noreply, assign(socket, form: to_form(changeset, action: :validate))}
  end

  def handle_event("save", %{"user" => user_params}, socket) do
    save_user(socket, socket.assigns.action, user_params)
  end

  def handle_event("cancel", _params, socket) do
    {:noreply, push_patch(socket, to: socket.assigns.patch)}
  end

  defp save_user(socket, :edit, user_params) do
    case update_user(socket.assigns.user, user_params) do
      {:ok, user} ->
        notify_parent({:saved, user})

        socket =
          socket
          |> put_flash(:info, "User updated successfully")
          |> push_patch(to: socket.assigns.patch)

        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  defp save_user(socket, :new, user_params) do
    case create_user(user_params) do
      {:ok, user} ->
        notify_parent({:saved, user})

        socket =
          socket
          |> put_flash(:info, "User created successfully")
          |> push_patch(to: socket.assigns.patch)

        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  defp create_user(attrs) do
    changeset = user_changeset(%User{}, attrs)

    Repo.transaction(fn ->
      case Repo.insert(changeset) do
        {:ok, user} ->
          # Assign roles if provided
          role_ids = extract_role_ids(attrs)
          assign_roles_to_user(user, role_ids)
          user

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  defp update_user(user, attrs) do
    changeset = user_changeset(user, attrs)

    Repo.transaction(fn ->
      case Repo.update(changeset) do
        {:ok, updated_user} ->
          # Update role assignments
          role_ids = extract_role_ids(attrs)
          update_user_roles(updated_user, role_ids)
          updated_user

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  defp user_changeset(user, attrs \\ %{}) do
    required_fields = [:email]
    optional_fields = [:name]

    all_fields =
      if user.id do
        required_fields ++ optional_fields
      else
        required_fields ++ optional_fields ++ [:password]
      end

    user
    |> cast(attrs, all_fields)
    |> validate_required(required_fields)
    |> validate_email()
    |> validate_password()
    |> unique_constraint(:email)
  end

  defp validate_email(changeset) do
    changeset
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> validate_length(:email, max: 160)
  end

  defp validate_password(changeset) do
    changeset
    |> validate_length(:password, min: 6, max: 72)
    |> validate_confirmation(:password, message: "does not match password")
    |> maybe_hash_password()
  end

  defp maybe_hash_password(changeset) do
    password = get_change(changeset, :password)

    if password && changeset.valid? do
      changeset
      |> put_change(:password_hash, hash_password(password))
      |> delete_change(:password)
      |> delete_change(:password_confirmation)
    else
      changeset
    end
  end

  defp hash_password(password) do
    Argon2.hash_pwd_salt(password)
  end

  defp extract_role_ids(attrs) do
    case attrs["role_ids"] do
      role_ids when is_list(role_ids) ->
        Enum.map(role_ids, &String.to_integer/1)

      _ ->
        []
    end
  end

  defp assign_roles_to_user(user, role_ids) do
    # Remove existing role assignments
    from(ur in "user_roles", where: ur.user_id == ^user.id)
    |> Repo.delete_all()

    # Insert new role assignments
    user_roles =
      Enum.map(role_ids, fn role_id ->
        %{
          user_id: user.id,
          role_id: role_id,
          inserted_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
          updated_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
        }
      end)

    if user_roles != [] do
      Repo.insert_all("user_roles", user_roles)
    end
  end

  defp update_user_roles(user, role_ids) do
    assign_roles_to_user(user, role_ids)
  end

  defp list_roles do
    from(r in Role, order_by: r.name)
    |> Repo.all()
  end

  defp get_user_role_ids(nil), do: []

  defp get_user_role_ids(user_id) do
    from(ur in "user_roles",
      where: ur.user_id == ^user_id,
      select: ur.role_id
    )
    |> Repo.all()
  end

  defp notify_parent(msg), do: send(self(), {__MODULE__, msg})
end
