defmodule BaseAclEx.Accounts.Application.Queries.GetUserByIdQuery do
  @moduledoc """
  Query to retrieve a user by their ID.
  """

  use BaseAclEx.SharedKernel.CQRS.Query

  @enforce_keys [:user_id]
  defstruct [:user_id, :include_permissions, :include_roles]

  @doc """
  Creates a new query to get user by ID.
  """
  def new(user_id, opts \\ []) do
    %__MODULE__{
      user_id: user_id,
      include_permissions: Keyword.get(opts, :include_permissions, false),
      include_roles: Keyword.get(opts, :include_roles, false)
    }
  end

  @impl true
  def validate(query) do
    if is_nil(query.user_id) || query.user_id == "" do
      {:error, [{:user_id, "is required"}]}
    else
      {:ok, query}
    end
  end

  @impl true
  def cache_config(query) do
    [
      enabled: true,
      ttl: :timer.minutes(5),
      key: "user:#{query.user_id}"
    ]
  end
end
