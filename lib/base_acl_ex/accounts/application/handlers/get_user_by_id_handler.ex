defmodule BaseAclEx.Accounts.Application.Handlers.GetUserByIdHandler do
  @moduledoc """
  Handler for retrieving user by ID query.
  """
  
  use BaseAclEx.SharedKernel.CQRS.QueryHandler
  
  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Infrastructure.Persistence.Repo
  alias BaseAclEx.Accounts.Application.Queries.GetUserByIdQuery
  
  @impl true
  def execute(%GetUserByIdQuery{} = query) do
    case Repo.get(User, query.user_id) do
      nil ->
        {:error, :user_not_found}
      
      user ->
        user = maybe_preload_associations(user, query)
        {:ok, format_user_response(user, query)}
    end
  end
  
  defp maybe_preload_associations(user, query) do
    preloads = []
    
    preloads = if query.include_roles do
      [:roles | preloads]
    else
      preloads
    end
    
    preloads = if query.include_permissions do
      [:permissions | preloads]
    else
      preloads
    end
    
    if Enum.empty?(preloads) do
      user
    else
      # Repo.preload(user, preloads)
      user
    end
  end
  
  defp format_user_response(user, query) do
    response = %{
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
    
    response = if query.include_roles do
      Map.put(response, :roles, format_roles(Map.get(user, :roles, [])))
    else
      response
    end
    
    response = if query.include_permissions do
      Map.put(response, :permissions, format_permissions(Map.get(user, :permissions, [])))
    else
      response
    end
    
    response
  end
  
  defp format_roles(roles) do
    Enum.map(roles, fn role ->
      %{
        id: role.id,
        name: role.name,
        slug: role.slug,
        description: role.description
      }
    end)
  end
  
  defp format_permissions(permissions) do
    Enum.map(permissions, fn permission ->
      %{
        id: permission.id,
        name: permission.name,
        resource: permission.resource,
        action: permission.action,
        context: permission.context
      }
    end)
  end
end