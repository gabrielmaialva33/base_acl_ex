defmodule BaseAclExWeb.Api.V1.AuthController do
  @moduledoc """
  Authentication controller for API v1.
  Handles user registration, login, logout, and token refresh.
  """

  use BaseAclExWeb, :controller

  alias BaseAclEx.Accounts.Application.Commands.{AuthenticateUserCommand, RegisterUserCommand}
  alias BaseAclEx.Accounts.Application.Handlers.{AuthenticateUserHandler, RegisterUserHandler}
  alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl
  alias BaseAclEx.Infrastructure.Security.Services.TokenStore

  action_fallback BaseAclExWeb.FallbackController

  @doc """
  Register a new user.
  """
  def register(conn, params) do
    command = RegisterUserCommand.new(params)

    with {:ok, command} <- RegisterUserCommand.validate(command),
         {:ok, result} <- RegisterUserHandler.execute(command) do
      conn
      |> put_status(:created)
      |> render(:user, user: result.user)
    end
  end

  @doc """
  Authenticate user and return JWT tokens.
  """
  def login(conn, %{"email" => email, "password" => password} = params) do
    command =
      AuthenticateUserCommand.new(%{
        email: email,
        password: password,
        ip_address: get_ip_address(conn),
        user_agent: get_user_agent(conn),
        remember_me: Map.get(params, "remember_me", false)
      })

    with {:ok, command} <- AuthenticateUserCommand.validate(command),
         {:ok, result} <- AuthenticateUserHandler.execute(command) do
      conn
      |> put_status(:ok)
      |> render(:login, user: result.user, tokens: result.tokens)
    end
  end

  @doc """
  Refresh access token using refresh token.
  """
  def refresh(conn, %{"refresh_token" => refresh_token}) do
    with {:ok, tokens} <- GuardianImpl.refresh_access_token(refresh_token) do
      conn
      |> put_status(:ok)
      |> render(:tokens, tokens: tokens)
    end
  end

  @doc """
  Logout user and revoke tokens.
  """
  def logout(conn, %{"all_devices" => true}) do
    user = Guardian.Plug.current_resource(conn)

    with {:ok, result} <- GuardianImpl.revoke_all_user_tokens(user.id, user.id, "logout_all") do
      conn
      |> put_status(:ok)
      |> render(:logout_all, result: result)
    end
  end

  def logout(conn, _params) do
    token = Guardian.Plug.current_token(conn)

    with {:ok, _claims} <- GuardianImpl.revoke_token(token) do
      conn
      |> put_status(:ok)
      |> render(:logout)
    end
  end

  @doc """
  Get current user information.
  """
  def me(conn, _params) do
    user = Guardian.Plug.current_resource(conn)

    conn
    |> put_status(:ok)
    |> render(:user, user: user)
  end

  @doc """
  Verify if token is valid.
  """
  def verify(conn, _params) do
    user = Guardian.Plug.current_resource(conn)

    if user do
      conn
      |> put_status(:ok)
      |> render(:verify, valid: true, user: user)
    else
      conn
      |> put_status(:unauthorized)
      |> render(:verify, valid: false, user: nil)
    end
  end

  # Private functions

  defp get_ip_address(conn) do
    conn.remote_ip
    |> Tuple.to_list()
    |> Enum.join(".")
  end

  defp get_user_agent(conn) do
    conn
    |> get_req_header("user-agent")
    |> List.first()
  end

  @doc """
  Get user devices and active sessions.
  """
  def devices(conn, _params) do
    user = Guardian.Plug.current_resource(conn)

    with {:ok, devices} <- GuardianImpl.get_user_devices(user.id) do
      conn
      |> put_status(:ok)
      |> render(:devices, devices: devices)
    end
  end

  @doc """
  Revoke tokens for a specific device.
  """
  def revoke_device(conn, %{"device_id" => device_id}) do
    user = Guardian.Plug.current_resource(conn)

    with {:ok, result} <- GuardianImpl.revoke_device_tokens(user.id, device_id, user.id) do
      conn
      |> put_status(:ok)
      |> render(:revoke_device, result: result)
    end
  end

  @doc """
  Get token usage statistics.
  """
  def token_stats(conn, _params) do
    user = Guardian.Plug.current_resource(conn)

    with {:ok, stats} <- GuardianImpl.get_user_token_stats(user.id) do
      conn
      |> put_status(:ok)
      |> render(:token_stats, stats: stats)
    end
  end
end
