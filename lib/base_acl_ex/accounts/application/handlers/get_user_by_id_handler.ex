defmodule BaseAclEx.Accounts.Application.Handlers.GetUserByIdHandler do
  @moduledoc """
  Handler for retrieving user by ID query.
  """

  use BaseAclEx.SharedKernel.CQRS.QueryHandler

  alias BaseAclEx.Accounts.Application.Queries.GetUserByIdQuery
  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Infrastructure.Persistence.Repo
  alias BaseAclExWeb.Formatters.UserFormatter

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

    preloads =
      if query.include_roles do
        [:roles | preloads]
      else
        preloads
      end

    preloads =
      if query.include_permissions do
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
    response = UserFormatter.format_user(user)

    response =
      if query.include_roles do
        Map.put(response, :roles, UserFormatter.format_roles(Map.get(user, :roles, [])))
      else
        response
      end

    response =
      if query.include_permissions do
        Map.put(
          response,
          :permissions,
          UserFormatter.format_permissions(Map.get(user, :permissions, []))
        )
      else
        response
      end

    response
  end
end
