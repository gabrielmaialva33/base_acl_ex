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
      |> BaseAclEx.Accounts.create_user()

    user
  end
end
