defmodule BaseAclExWeb.Api.V1.PermissionJSON do
  @moduledoc """
  JSON view for permission responses.
  """

  @doc """
  Renders a list of permissions.
  """
  def index(%{permissions: permissions, pagination: pagination}) do
    %{
      data: Enum.map(permissions, &permission_data/1),
      meta: pagination_meta(pagination)
    }
  end

  @doc """
  Renders a single permission.
  """
  def show(%{permission: permission}) do
    %{data: permission_data_with_roles(permission)}
  end

  @doc """
  Renders roles that have this permission.
  """
  def roles(%{roles: roles, pagination: pagination}) do
    %{
      data: Enum.map(roles, &role_assignment_data/1),
      meta: pagination_meta(pagination)
    }
  end

  @doc """
  Renders permission assignment confirmation.
  """
  def assign_role(_) do
    %{
      data: %{
        message: "Permission successfully assigned to role"
      }
    }
  end

  @doc """
  Renders permission removal confirmation.
  """
  def remove_role(_) do
    %{
      data: %{
        message: "Permission successfully removed from role"
      }
    }
  end

  @doc """
  Renders delete confirmation.
  """
  def delete(_) do
    %{
      data: %{
        message: "Permission successfully deleted"
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

  defp permission_data(permission) do
    %{
      id: permission.id,
      name: permission.name,
      slug: permission.slug,
      resource: permission.resource,
      action: permission.action,
      scope: permission.scope,
      description: permission.description,
      is_system: permission.is_system,
      metadata: permission.metadata || %{},
      created_at: permission.inserted_at,
      updated_at: permission.updated_at
    }
  end

  defp permission_data_with_roles(permission) do
    base_data = permission_data(permission)
    
    roles = 
      case permission.roles do
        %Ecto.Association.NotLoaded{} -> []
        role_list -> Enum.map(role_list, &role_data/1)
      end

    Map.put(base_data, :roles, roles)
  end

  defp role_data(role) do
    %{
      id: role.id,
      name: role.name,
      slug: role.slug,
      description: role.description,
      priority: role.priority
    }
  end

  defp role_assignment_data(assignment) do
    %{
      role: %{
        id: assignment.role.id,
        name: assignment.role.name,
        slug: assignment.role.slug,
        description: assignment.role.description
      },
      granted_at: assignment.granted_at,
      granted_by: assignment.granted_by
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