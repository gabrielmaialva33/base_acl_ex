defmodule BaseAclExWeb.Views.TokenView do
  alias BaseAclEx.Repo
  alias BaseAclEx.Accounts.Models.User

  def for_token(user), do: {:ok, "User:#{user.id}"}
  def for_token(_), do: {:error, "Unknown resource type"}

  def from_token("User:" <> id), do: {:ok, Repo.get(User, id)}
  def from_token(_), do: {:error, "Unknown resource type"}
end
