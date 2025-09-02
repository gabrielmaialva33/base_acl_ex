defmodule BaseAclExWeb.Formatters.UserFormatter do
  @moduledoc """
  Shared formatter for user data across controllers and handlers.
  """

  @doc """
  Formats user data into a consistent structure for API responses.
  """
  def format_user(user) do
    %{
      id: user.id,
      email: user.email,
      username: user.username,
      first_name: user.first_name,
      last_name: user.last_name,
      phone_number: user.phone_number,
      avatar_url: user.avatar_url,
      email_verified: user.email_verified_at != nil,
      two_factor_enabled: user.two_factor_enabled,
      created_at: user.inserted_at,
      updated_at: user.updated_at
    }
  end

  @doc """
  Formats a list of roles.
  """
  def format_roles(roles) when is_list(roles) do
    Enum.map(roles, &format_role/1)
  end

  def format_roles(_), do: []

  @doc """
  Formats a single role.
  """
  def format_role(role) do
    %{
      id: role.id,
      name: role.name,
      slug: role.slug,
      description: role.description
    }
  end

  @doc """
  Formats a list of permissions.
  """
  def format_permissions(permissions) when is_list(permissions) do
    Enum.map(permissions, &format_permission/1)
  end

  def format_permissions(_), do: []

  @doc """
  Formats a single permission.
  """
  def format_permission(permission) do
    %{
      id: permission.id,
      name: permission.name,
      slug: permission.slug,
      resource: permission.resource,
      action: permission.action,
      scope: permission.scope
    }
  end
end
