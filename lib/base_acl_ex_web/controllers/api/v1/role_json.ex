defmodule BaseAclExWeb.Api.V1.RoleJSON do
  @moduledoc """
  JSON view for role responses.
  """

  @doc """
  Renders a list of roles.
  """
  def index(%{roles: roles, pagination: pagination}) do
    %{
      data: Enum.map(roles, &role_data/1),
      meta: pagination_meta(pagination)
    }
  end

  @doc """
  Renders a single role.
  """
  def show(%{role: role}) do
    %{data: role_data_with_permissions(role)}
  end

  @doc """
  Renders users assigned to a role.
  """
  def users(%{users: users, pagination: pagination}) do
    %{
      data: Enum.map(users, &user_assignment_data/1),
      meta: pagination_meta(pagination)
    }
  end

  @doc """
  Renders role assignment confirmation.
  """
  def assign_user(_) do
    %{
      data: %{
        message: "Role successfully assigned to user"
      }
    }
  end

  @doc """
  Renders role removal confirmation.
  """
  def remove_user(_) do
    %{
      data: %{
        message: "Role successfully removed from user"
      }
    }
  end

  @doc """
  Renders delete confirmation.
  """
  def delete(_) do
    %{
      data: %{
        message: "Role successfully deleted"
      }
    }
  end

  @doc """
  Renders errors.
  """
  def error(%{changeset: changeset}) do
    %{
      errors: translate_errors(changeset)
    }
  end

  def error(%{message: message}) do
    %{
      error: %{
        message: message
      }
    }
  end

  # Private functions

  defp role_data(role) do
    %{
      id: role.id,
      name: role.name,
      slug: role.slug,
      description: role.description,
      priority: role.priority,
      is_system: role.is_system,
      metadata: role.metadata || %{},
      created_at: role.inserted_at,
      updated_at: role.updated_at
    }
  end

  defp role_data_with_permissions(role) do
    base_data = role_data(role)

    permissions =
      case role.permissions do
        %Ecto.Association.NotLoaded{} -> []
        perms -> Enum.map(perms, &permission_data/1)
      end

    Map.put(base_data, :permissions, permissions)
  end

  defp permission_data(permission) do
    %{
      id: permission.id,
      name: permission.name,
      slug: permission.slug,
      resource: permission.resource,
      action: permission.action,
      scope: permission.scope,
      description: permission.description
    }
  end

  defp user_assignment_data(assignment) do
    %{
      user: %{
        id: assignment.user.id,
        email: assignment.user.email,
        username: assignment.user.username,
        first_name: assignment.user.first_name,
        last_name: assignment.user.last_name
      },
      assigned_at: assignment.assigned_at,
      assigned_by: assignment.assigned_by
    }
  end

  defp pagination_meta(pagination) do
    %{
      current_page: pagination.page_number,
      per_page: pagination.page_size,
      total_pages: pagination.total_pages,
      total_entries: pagination.total_entries
    }
  end

  defp translate_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
