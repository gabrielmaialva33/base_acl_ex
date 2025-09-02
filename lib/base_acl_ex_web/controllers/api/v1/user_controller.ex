defmodule BaseAclExWeb.Api.V1.UserController do
  @moduledoc """
  User management controller for API v1.
  Handles CRUD operations for users.
  """

  use BaseAclExWeb, :controller
  import Ecto.Query

  alias BaseAclEx.Accounts.Application.Handlers.{GetUserByIdHandler, GetUserPermissionsHandler}
  alias BaseAclEx.Accounts.Application.Queries.{GetUserByIdQuery, GetUserPermissionsQuery}
  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Infrastructure.Persistence.Repo

  action_fallback BaseAclExWeb.FallbackController

  @doc """
  List all users with pagination.
  """
  def index(conn, params) do
    page = Map.get(params, "page", "1") |> String.to_integer()
    per_page = Map.get(params, "per_page", "20") |> String.to_integer()
    search = Map.get(params, "search", "")

    query =
      from(u in User,
        where: u.deleted_at |> is_nil(),
        order_by: [desc: u.inserted_at]
      )

    query =
      if search != "" do
        search_term = "%#{search}%"

        from(u in query,
          where:
            ilike(u.email, ^search_term) or
              ilike(u.username, ^search_term) or
              ilike(u.first_name, ^search_term) or
              ilike(u.last_name, ^search_term)
        )
      else
        query
      end

    page = Repo.paginate(query, page: page, page_size: per_page)

    conn
    |> put_status(:ok)
    |> render(:index, users: page.entries, pagination: page)
  end

  @doc """
  Get a specific user by ID.
  """
  def show(conn, %{"id" => user_id}) do
    query =
      GetUserByIdQuery.new(user_id,
        include_roles: true,
        include_permissions: false
      )

    with {:ok, query} <- GetUserByIdQuery.validate(query),
         {:ok, user} <- GetUserByIdHandler.execute(query) do
      conn
      |> put_status(:ok)
      |> render(:show, user: user)
    end
  end

  @doc """
  Update user information.
  """
  def update(conn, %{"id" => user_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    # Check if user can update (self or admin)
    if current_user.id == user_id || has_admin_permission?(current_user) do
      user = Repo.get!(User, user_id)

      attrs =
        params
        |> Map.take(["first_name", "last_name", "username", "phone_number", "avatar_url"])

      case user |> User.update_changeset(attrs) |> Repo.update() do
        {:ok, updated_user} ->
          conn
          |> put_status(:ok)
          |> render(:show, user: format_user(updated_user))

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> render(:error, changeset: changeset)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to update this user")
    end
  end

  @doc """
  Delete a user (soft delete).
  """
  def delete(conn, %{"id" => user_id}) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      user = Repo.get!(User, user_id)

      case user |> User.delete_changeset() |> Repo.update() do
        {:ok, _} ->
          conn
          |> put_status(:ok)
          |> render(:delete)

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> render(:error, changeset: changeset)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to delete users")
    end
  end

  @doc """
  Get user permissions.
  """
  def permissions(conn, %{"id" => user_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    # Check if user can view permissions (self or admin)
    if current_user.id == user_id || has_admin_permission?(current_user) do
      query =
        GetUserPermissionsQuery.new(user_id,
          scope: Map.get(params, "scope", "any"),
          include_inherited: Map.get(params, "include_inherited", "true") == "true",
          active_only: Map.get(params, "active_only", "true") == "true"
        )

      with {:ok, query} <- GetUserPermissionsQuery.validate(query),
           {:ok, permissions} <- GetUserPermissionsHandler.execute(query) do
        conn
        |> put_status(:ok)
        |> render(:permissions, permissions: permissions)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to view user permissions")
    end
  end

  # Private functions

  defp has_admin_permission?(user) do
    # Check if user has admin role or permission
    # This would check the actual permissions
    false
  end

  defp format_user(user) do
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
end
