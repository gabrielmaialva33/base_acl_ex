defmodule BaseAclEx.Accounts.Repositories.UserRepository do
  @moduledoc """
  The User context repository.
  """

  import Ecto.Query, warn: false
  alias BaseAclEx.Repo
  alias Flop

  alias BaseAclEx.Accounts.Models.User
  alias BaseAclEx.Accounts.Repositories.{RoleRepository}

  @doc """
  Returns the list of users.

  ## Examples

      iex> list_users()
      [%User{}, ...]

  """
  @spec list_users(Flop.t()) ::
          {:ok, {[User.t()], Flop.Meta.t()}} | {:error, Changeset.t()}
  def list_users(flop \\ %Flop{}) do
    query =
      from u in User,
        where: u.is_deleted != true,
        order_by: [u.first_name, u.last_name, u.username, u.email],
        preload: [:roles]

    Flop.validate_and_run(query, flop, for: User)
  end

  @doc """
  Gets a single user.

  Raises `Ecto.NoResultsError` if the User does not exist.

  ## Examples

      iex> get_user!(123)
      %User{}

      iex> get_user!(456)
      ** (Ecto.NoResultsError)

  """
  def get_user!(id), do: Repo.get!(User, id)

  @doc """
  Gets a single user.
  """
  def get_user(id) do
    query =
      from u in User, where: u.id == ^id and u.is_deleted != true, preload: [:roles], limit: 1

    Repo.one!(query)
  end

  @doc """
  Creates a user.

  ## Examples

      iex> create_user(%{field: value})
      {:ok, %User{}}

      iex> create_user(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_user(attrs \\ %{}) do
    %User{}
    |> User.changeset(attrs)
    |> Ecto.Changeset.put_assoc(:roles, [RoleRepository.get_role_by_name("user")])
    |> Repo.insert()
  end

  @doc """
  Updates a user.

  ## Examples

      iex> update_user(user, %{field: new_value})
      {:ok, %User{}}

      iex> update_user(user, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_user(%User{} = user, attrs) do
    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a user.

  ## Examples

      iex> delete_user(user)
      {:ok, %User{}}

      iex> delete_user(user)
      {:error, %Ecto.Changeset{}}

  """
  def delete_user(%User{} = user) do
    Repo.delete(user)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking user changes.

  ## Examples

      iex> change_user(user)
      %Ecto.Changeset{data: %User{}}

  """
  def change_user(%User{} = user, attrs \\ %{}) do
    User.changeset(user, attrs)
  end
end
