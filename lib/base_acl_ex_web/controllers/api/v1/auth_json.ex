defmodule BaseAclExWeb.Api.V1.AuthJSON do
  @moduledoc """
  JSON view for authentication responses.
  """

  @doc """
  Renders user registration response.
  """
  def user(%{user: user}) do
    %{
      data: %{
        id: user.id,
        email: user.email,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        created_at: user.inserted_at
      }
    }
  end

  @doc """
  Renders login response with tokens.
  """
  def login(%{user: user, tokens: tokens}) do
    %{
      data: %{
        user: %{
          id: user.id,
          email: user.email,
          username: user.username,
          first_name: user.first_name,
          last_name: user.last_name
        },
        tokens: %{
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          token_type: tokens.token_type,
          expires_in: tokens.expires_in
        }
      }
    }
  end

  @doc """
  Renders token refresh response.
  """
  def tokens(%{tokens: tokens}) do
    %{
      data: %{
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in
      }
    }
  end

  @doc """
  Renders logout response.
  """
  def logout(_) do
    %{
      data: %{
        message: "Successfully logged out"
      }
    }
  end

  @doc """
  Renders token verification response.
  """
  def verify(%{valid: valid, user: user}) do
    %{
      data: %{
        valid: valid,
        user:
          if user do
            %{
              id: user.id,
              email: user.email,
              username: user.username
            }
          else
            nil
          end
      }
    }
  end
end
