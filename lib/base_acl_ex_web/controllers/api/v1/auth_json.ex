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

  @doc """
  Renders logout all devices response.
  """
  def logout_all(%{result: result}) do
    %{
      data: %{
        message: "Successfully logged out from all devices",
        revoked_tokens: result.revoked_count
      }
    }
  end

  @doc """
  Renders user devices response.
  """
  def devices(%{devices: devices}) do
    %{
      data: %{
        devices: Enum.map(devices, &render_device/1)
      }
    }
  end

  @doc """
  Renders device revocation response.
  """
  def revoke_device(%{result: result}) do
    %{
      data: %{
        message: "Device tokens revoked successfully",
        revoked_tokens: result.revoked_count
      }
    }
  end

  @doc """
  Renders token statistics response.
  """
  def token_stats(%{stats: stats}) do
    %{
      data: %{
        active_tokens: stats.active_tokens,
        revoked_tokens: stats.revoked_tokens,
        expired_tokens: stats.expired_tokens,
        total_tokens: stats.total_tokens,
        last_used_at: stats.last_used_at
      }
    }
  end

  # Private helpers

  defp render_device(device) do
    %{
      device_id: device.device_id,
      device_name: device.device_name,
      user_agent: device.user_agent,
      last_used_at: device.last_used_at,
      token_count: device.token_count
    }
  end
end
