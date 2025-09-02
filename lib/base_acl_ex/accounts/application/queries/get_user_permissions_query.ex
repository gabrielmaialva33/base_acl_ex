defmodule BaseAclEx.Accounts.Application.Queries.GetUserPermissionsQuery do
  @moduledoc """
  Query to retrieve all permissions for a user.
  """

  use BaseAclEx.SharedKernel.CQRS.Query

  @enforce_keys [:user_id]
  defstruct [:user_id, :scope, :include_inherited, :active_only]

  @doc """
  Creates a new query to get user permissions.
  """
  def new(user_id, opts \\ []) do
    %__MODULE__{
      user_id: user_id,
      scope: Keyword.get(opts, :scope, "any"),
      include_inherited: Keyword.get(opts, :include_inherited, true),
      active_only: Keyword.get(opts, :active_only, true)
    }
  end

  @impl true
  def validate(query) do
    errors = []

    errors =
      if is_nil(query.user_id) || query.user_id == "" do
        [{:user_id, "is required"} | errors]
      else
        errors
      end

    errors =
      if query.scope in ["any", "own", "team", "department", "organization", "global"] do
        errors
      else
        [{:scope, "is invalid"} | errors]
      end

    if Enum.empty?(errors) do
      {:ok, query}
    else
      {:error, errors}
    end
  end

  @impl true
  def cache_config(query) do
    [
      enabled: true,
      ttl: :timer.minutes(10),
      key: "user_permissions:#{query.user_id}:#{query.scope}"
    ]
  end
end
