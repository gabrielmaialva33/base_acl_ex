defmodule BaseAclExWeb.Api.V1.UserJSON do
  @moduledoc """
  JSON view for user responses.
  """

  @doc """
  Renders a list of users.
  """
  def index(%{users: users, pagination: pagination}) do
    %{
      data: Enum.map(users, &user_data/1),
      meta: pagination_meta(pagination)
    }
  end

  @doc """
  Renders a single user.
  """
  def show(%{user: user}) do
    %{data: user_data(user)}
  end

  @doc """
  Renders user permissions.
  """
  def permissions(%{permissions: permissions}) do
    %{
      data: %{
        permissions: Enum.map(permissions, &permission_data/1),
        total: length(permissions)
      }
    }
  end

  @doc """
  Renders delete confirmation.
  """
  def delete(_) do
    %{
      data: %{
        message: "User successfully deleted"
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

  defp user_data(user) when is_map(user) do
    %{
      id: Map.get(user, :id),
      email: Map.get(user, :email),
      username: Map.get(user, :username),
      first_name: Map.get(user, :first_name),
      last_name: Map.get(user, :last_name),
      phone_number: Map.get(user, :phone_number),
      avatar_url: Map.get(user, :avatar_url),
      email_verified: Map.get(user, :email_verified, false),
      two_factor_enabled: Map.get(user, :two_factor_enabled, false),
      roles: Map.get(user, :roles, []) |> Enum.map(&role_data/1),
      created_at: Map.get(user, :created_at),
      updated_at: Map.get(user, :updated_at)
    }
  end

  defp role_data(role) do
    %{
      id: Map.get(role, :id),
      name: Map.get(role, :name),
      slug: Map.get(role, :slug),
      description: Map.get(role, :description)
    }
  end

  defp permission_data(permission) do
    %{
      name: Map.get(permission, :name),
      resource: Map.get(permission, :resource),
      action: Map.get(permission, :action),
      context: Map.get(permission, :context),
      granted_at: Map.get(permission, :granted_at),
      expires_at: Map.get(permission, :expires_at),
      source: Map.get(permission, :source)
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
