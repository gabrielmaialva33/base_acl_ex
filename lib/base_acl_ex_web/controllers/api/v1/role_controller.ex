defmodule BaseAclExWeb.Api.V1.RoleController do
  @moduledoc """
  Role management controller for API v1.
  Handles CRUD operations for roles and role assignments.
  """

  use BaseAclExWeb, :controller
  import Ecto.Query

  alias BaseAclEx.Accounts.Application.Commands.{
    AssignRoleToUserCommand,
    RemoveRoleFromUserCommand
  }

  alias BaseAclEx.Accounts.Application.Handlers.{
    AssignRoleToUserHandler,
    RemoveRoleFromUserHandler
  }

  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.Identity.Core.Entities.UserRole
  alias BaseAclEx.Infrastructure.Persistence.Repo

  action_fallback BaseAclExWeb.FallbackController

  @doc """
  List all roles with pagination.
  """
  def index(conn, params) do
    page = Map.get(params, "page", "1") |> String.to_integer()
    per_page = Map.get(params, "per_page", "20") |> String.to_integer()
    search = Map.get(params, "search", "")

    query =
      from(r in Role,
        where: r.deleted_at |> is_nil(),
        order_by: [asc: r.priority, asc: r.name]
      )

    query =
      if search != "" do
        search_term = "%#{search}%"

        from(r in query,
          where:
            ilike(r.name, ^search_term) or
              ilike(r.slug, ^search_term) or
              ilike(r.description, ^search_term)
        )
      else
        query
      end

    page = Repo.paginate(query, page: page, page_size: per_page)

    conn
    |> put_status(:ok)
    |> render(:index, roles: page.entries, pagination: page)
  end

  @doc """
  Get a specific role by ID.
  """
  def show(conn, %{"id" => role_id}) do
    role =
      from(r in Role,
        where: r.id == ^role_id and is_nil(r.deleted_at),
        preload: [:permissions]
      )
      |> Repo.one()

    case role do
      nil ->
        {:error, :not_found}

      role ->
        conn
        |> put_status(:ok)
        |> render(:show, role: role)
    end
  end

  @doc """
  Create a new role.
  """
  def create(conn, params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      attrs = %{
        name: Map.get(params, "name"),
        slug: Map.get(params, "slug"),
        description: Map.get(params, "description"),
        priority: Map.get(params, "priority", 100),
        metadata: Map.get(params, "metadata", %{}),
        is_system: Map.get(params, "is_system", false)
      }

      changeset = Role.changeset(%Role{}, attrs)

      case Repo.insert(changeset) do
        {:ok, role} ->
          conn
          |> put_status(:created)
          |> render(:show, role: role)

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> render(:error, changeset: changeset)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to create roles")
    end
  end

  @doc """
  Update role information.
  """
  def update(conn, %{"id" => role_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      role = Repo.get!(Role, role_id)

      attrs =
        params
        |> Map.take(["name", "description", "priority", "metadata"])

      changeset = Role.changeset(role, attrs)

      case Repo.update(changeset) do
        {:ok, updated_role} ->
          conn
          |> put_status(:ok)
          |> render(:show, role: updated_role)

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> render(:error, changeset: changeset)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to update roles")
    end
  end

  @doc """
  Delete a role (soft delete).
  """
  def delete(conn, %{"id" => role_id}) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      role = Repo.get!(Role, role_id)

      if role.is_system do
        conn
        |> put_status(:forbidden)
        |> render(:error, message: "System roles cannot be deleted")
      else
        changeset = Role.changeset(role, %{deleted_at: DateTime.utc_now()})

        case Repo.update(changeset) do
          {:ok, _} ->
            conn
            |> put_status(:ok)
            |> render(:delete)

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> render(:error, changeset: changeset)
        end
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to delete roles")
    end
  end

  @doc """
  Get users assigned to a role.
  """
  def users(conn, %{"id" => role_id} = params) do
    page = Map.get(params, "page", "1") |> String.to_integer()
    per_page = Map.get(params, "per_page", "20") |> String.to_integer()

    query =
      from(ur in UserRole,
        join: u in User,
        on: ur.user_id == u.id,
        where: ur.role_id == ^role_id and is_nil(ur.revoked_at),
        select: %{
          user: u,
          assigned_at: ur.inserted_at,
          assigned_by: ur.assigned_by
        },
        order_by: [desc: ur.inserted_at]
      )

    page = Repo.paginate(query, page: page, page_size: per_page)

    conn
    |> put_status(:ok)
    |> render(:users, users: page.entries, pagination: page)
  end

  @doc """
  Assign a role to a user.
  """
  def assign_user(conn, %{"id" => role_id, "user_id" => user_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      command =
        AssignRoleToUserCommand.new(%{
          user_id: user_id,
          role_id: role_id,
          assigned_by: current_user.id,
          expires_at: Map.get(params, "expires_at"),
          reason: Map.get(params, "reason"),
          metadata: Map.get(params, "metadata", %{})
        })

      with {:ok, command} <- AssignRoleToUserCommand.validate(command),
           {:ok, _assignment} <- AssignRoleToUserHandler.execute(command) do
        conn
        |> put_status(:ok)
        |> render(:assign_user)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to assign roles")
    end
  end

  @doc """
  Remove a role from a user.
  """
  def remove_user(conn, %{"id" => role_id, "user_id" => user_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      command =
        RemoveRoleFromUserCommand.new(%{
          user_id: user_id,
          role_id: role_id,
          revoked_by: current_user.id,
          reason: Map.get(params, "reason")
        })

      with {:ok, command} <- RemoveRoleFromUserCommand.validate(command),
           {:ok, _} <- RemoveRoleFromUserHandler.execute(command) do
        conn
        |> put_status(:ok)
        |> render(:remove_user)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to remove roles")
    end
  end

  # Private functions

  defp has_admin_permission?(user) do
    # Check if user has admin role or permission
    # This would check the actual permissions
    query =
      from(ur in UserRole,
        join: r in Role,
        on: ur.role_id == r.id,
        where: ur.user_id == ^user.id and is_nil(ur.revoked_at),
        where: r.slug in ["admin", "super-admin"],
        limit: 1
      )

    Repo.exists?(query)
  end
end
