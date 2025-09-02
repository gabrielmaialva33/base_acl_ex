defmodule BaseAclExWeb.Api.V1.PermissionController do
  @moduledoc """
  Permission management controller for API v1.
  Handles CRUD operations for permissions.
  """

  use BaseAclExWeb, :controller
  import Ecto.Query

  alias BaseAclEx.Authorization.Core.Entities.{Permission, RolePermission}
  alias BaseAclEx.Authorization.Core.Entities.Role
  alias BaseAclEx.Infrastructure.Persistence.Repo

  action_fallback BaseAclExWeb.FallbackController

  @doc """
  List all permissions with pagination.
  """
  def index(conn, params) do
    page = Map.get(params, "page", "1") |> String.to_integer()
    per_page = Map.get(params, "per_page", "20") |> String.to_integer()
    search = Map.get(params, "search", "")
    resource = Map.get(params, "resource")
    action = Map.get(params, "action")

    query =
      from(p in Permission,
        where: p.deleted_at |> is_nil(),
        order_by: [asc: p.resource, asc: p.action]
      )

    query =
      if search != "" do
        search_term = "%#{search}%"

        from(p in query,
          where:
            ilike(p.name, ^search_term) or
              ilike(p.slug, ^search_term) or
              ilike(p.description, ^search_term)
        )
      else
        query
      end

    query =
      if resource do
        from(p in query, where: p.resource == ^resource)
      else
        query
      end

    query =
      if action do
        from(p in query, where: p.action == ^action)
      else
        query
      end

    page = Repo.paginate(query, page: page, page_size: per_page)

    conn
    |> put_status(:ok)
    |> render(:index, permissions: page.entries, pagination: page)
  end

  @doc """
  Get a specific permission by ID.
  """
  def show(conn, %{"id" => permission_id}) do
    permission =
      from(p in Permission,
        where: p.id == ^permission_id and is_nil(p.deleted_at),
        preload: [:roles]
      )
      |> Repo.one()

    case permission do
      nil ->
        {:error, :not_found}

      permission ->
        conn
        |> put_status(:ok)
        |> render(:show, permission: permission)
    end
  end

  @doc """
  Create a new permission.
  """
  def create(conn, params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      attrs = %{
        name: Map.get(params, "name"),
        slug: Map.get(params, "slug"),
        resource: Map.get(params, "resource"),
        action: Map.get(params, "action"),
        scope: Map.get(params, "scope", "any"),
        description: Map.get(params, "description"),
        metadata: Map.get(params, "metadata", %{}),
        is_system: Map.get(params, "is_system", false)
      }

      changeset = Permission.changeset(%Permission{}, attrs)

      case Repo.insert(changeset) do
        {:ok, permission} ->
          conn
          |> put_status(:created)
          |> render(:show, permission: permission)

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> render(:error, changeset: changeset)
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to create permissions")
    end
  end

  @doc """
  Update permission information.
  """
  def update(conn, %{"id" => permission_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      permission = Repo.get!(Permission, permission_id)

      if permission.is_system do
        conn
        |> put_status(:forbidden)
        |> render(:error, message: "System permissions cannot be modified")
      else
        attrs =
          params
          |> Map.take(["name", "description", "scope", "metadata"])

        changeset = Permission.changeset(permission, attrs)

        case Repo.update(changeset) do
          {:ok, updated_permission} ->
            conn
            |> put_status(:ok)
            |> render(:show, permission: updated_permission)

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> render(:error, changeset: changeset)
        end
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to update permissions")
    end
  end

  @doc """
  Delete a permission (soft delete).
  """
  def delete(conn, %{"id" => permission_id}) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      permission = Repo.get!(Permission, permission_id)

      if permission.is_system do
        conn
        |> put_status(:forbidden)
        |> render(:error, message: "System permissions cannot be deleted")
      else
        changeset = Permission.changeset(permission, %{deleted_at: DateTime.utc_now()})

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
      |> render(:error, message: "You don't have permission to delete permissions")
    end
  end

  @doc """
  Get roles that have this permission.
  """
  def roles(conn, %{"id" => permission_id} = params) do
    page = Map.get(params, "page", "1") |> String.to_integer()
    per_page = Map.get(params, "per_page", "20") |> String.to_integer()

    query =
      from(rp in RolePermission,
        join: r in Role,
        on: rp.role_id == r.id,
        where: rp.permission_id == ^permission_id and is_nil(rp.revoked_at),
        select: %{
          role: r,
          granted_at: rp.inserted_at,
          granted_by: rp.granted_by
        },
        order_by: [desc: rp.inserted_at]
      )

    page = Repo.paginate(query, page: page, page_size: per_page)

    conn
    |> put_status(:ok)
    |> render(:roles, roles: page.entries, pagination: page)
  end

  @doc """
  Assign permission to a role.
  """
  def assign_role(conn, %{"id" => permission_id, "role_id" => role_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      existing =
        from(rp in RolePermission,
          where:
            rp.permission_id == ^permission_id and rp.role_id == ^role_id and
              is_nil(rp.revoked_at)
        )
        |> Repo.one()

      if existing do
        conn
        |> put_status(:conflict)
        |> render(:error, message: "Permission already assigned to this role")
      else
        attrs = %{
          permission_id: permission_id,
          role_id: role_id,
          granted_by: current_user.id,
          reason: Map.get(params, "reason"),
          metadata: Map.get(params, "metadata", %{})
        }

        changeset = RolePermission.changeset(%RolePermission{}, attrs)

        case Repo.insert(changeset) do
          {:ok, _} ->
            conn
            |> put_status(:ok)
            |> render(:assign_role)

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> render(:error, changeset: changeset)
        end
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to assign permissions")
    end
  end

  @doc """
  Remove permission from a role.
  """
  def remove_role(conn, %{"id" => permission_id, "role_id" => role_id} = params) do
    current_user = Guardian.Plug.current_resource(conn)

    if has_admin_permission?(current_user) do
      role_permission =
        from(rp in RolePermission,
          where:
            rp.permission_id == ^permission_id and rp.role_id == ^role_id and
              is_nil(rp.revoked_at)
        )
        |> Repo.one()

      case role_permission do
        nil ->
          conn
          |> put_status(:not_found)
          |> render(:error, message: "Permission not found for this role")

        rp ->
          changeset =
            RolePermission.changeset(rp, %{
              revoked_at: DateTime.utc_now(),
              revoked_by: current_user.id,
              revoked_reason: Map.get(params, "reason")
            })

          case Repo.update(changeset) do
            {:ok, _} ->
              conn
              |> put_status(:ok)
              |> render(:remove_role)

            {:error, changeset} ->
              conn
              |> put_status(:unprocessable_entity)
              |> render(:error, changeset: changeset)
          end
      end
    else
      conn
      |> put_status(:forbidden)
      |> render(:error, message: "You don't have permission to remove permissions")
    end
  end

  # Private functions

  defp has_admin_permission?(user) do
    # Check if user has admin role or permission
    query =
      from(ur in BaseAclEx.Authorization.Core.Entities.UserRole,
        join: r in Role,
        on: ur.role_id == r.id,
        where: ur.user_id == ^user.id and is_nil(ur.revoked_at),
        where: r.slug in ["admin", "super-admin"],
        limit: 1
      )

    Repo.exists?(query)
  end
end
