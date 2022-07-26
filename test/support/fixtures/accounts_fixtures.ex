defmodule BaseAclEx.AccountsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `BaseAclEx.Accounts` context.
  """

  @doc """
  Generate a user.
  """
  def user_fixture(attrs \\ %{}) do
    {:ok, user} =
      attrs
      |> Enum.into(%{
        email: "some email",
        firstname: "some firstname",
        is_deleted: true,
        lastname: "some lastname",
        password_hash: "some password_hash",
        username: "some username"
      })
      |> BaseAclEx.Accounts.Repositories.UserRepository.create_user()

    user
  end

  @doc """
  Generate a role.
  """
  def role_fixture(attrs \\ %{}) do
    {:ok, role} =
      attrs
      |> Enum.into(%{
        description: "some description",
        name: "some name",
        slug: "some slug"
      })
      |> BaseAclEx.Accounts.create_role()

    role
  end
end
