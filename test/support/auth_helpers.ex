defmodule BaseAclEx.TestSupport.AuthHelpers do
  @moduledoc """
  Authentication helpers for testing.
  Provides utilities for JWT tokens, authentication, and permission testing.
  """

  import Phoenix.ConnTest
  import ExUnit.Assertions
  import Plug.Conn

  alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl
  alias BaseAclEx.Factory

  @doc """
  Creates a JWT token for a user.
  """
  def create_token(user) do
    {:ok, token, _claims} = GuardianImpl.encode_and_sign(user)
    token
  end

  @doc """
  Authenticates a connection with a user's JWT token.
  """
  def authenticate_conn(conn, user) do
    token = create_token(user)
    put_req_header(conn, "authorization", "Bearer #{token}")
  end

  @doc """
  Creates and authenticates a connection with a default test user.
  """
  def authenticated_conn(conn, user_attrs \\ %{}) do
    user = Factory.insert_user(user_attrs)
    authenticate_conn(conn, user)
  end

  @doc """
  Creates and authenticates a connection with an admin user.
  """
  def admin_authenticated_conn(conn, user_attrs \\ %{}) do
    user = Factory.create_admin_user(user_attrs)
    authenticate_conn(conn, user)
  end

  @doc """
  Creates an authenticated connection with specific permissions.
  """
  def authenticated_conn_with_permissions(conn, permissions, user_attrs \\ %{}) do
    user = Factory.create_user_with_permissions(permissions)
    authenticate_conn(conn, user)
  end

  @doc """
  Extracts user from JWT token in Authorization header.
  """
  def extract_user_from_conn(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] ->
        case GuardianImpl.decode_and_verify(token) do
          {:ok, claims} ->
            case GuardianImpl.resource_from_claims(claims) do
              {:ok, user} -> user
              _ -> nil
            end

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  @doc """
  Asserts that a response is unauthorized (401).
  """
  def assert_unauthorized(conn) do
    assert conn.status == 401
    assert json_response(conn, 401)["error"] in ["unauthorized", "invalid_token"]
  end

  @doc """
  Asserts that a response is forbidden (403).
  """
  def assert_forbidden(conn) do
    assert conn.status == 403
    assert json_response(conn, 403)["error"] in ["forbidden", "insufficient_permissions"]
  end

  @doc """
  Asserts that a response requires authentication.
  """
  def assert_requires_auth(conn) do
    assert conn.status in [401, 403]
  end

  @doc """
  Creates authentication command data for testing.
  """
  def valid_auth_params(user \\ nil) do
    user = user || Factory.build_user()

    %{
      "email" => user.email,
      "password" => user.password || "SecurePass123!"
    }
  end

  @doc """
  Creates invalid authentication parameters.
  """
  def invalid_auth_params do
    %{
      "email" => "invalid@example.com",
      "password" => "wrongpassword"
    }
  end

  @doc """
  Creates registration parameters.
  """
  def valid_registration_params(attrs \\ %{}) do
    defaults = %{
      "email" => unique_email(),
      "password" => "SecurePass123!",
      "password_confirmation" => "SecurePass123!",
      "first_name" => "John",
      "last_name" => "Doe",
      "username" => unique_username()
    }

    Map.merge(defaults, stringify_keys(attrs))
  end

  @doc """
  Creates a mock IP address for testing.
  """
  def mock_ip_address, do: {127, 0, 0, 1}

  @doc """
  Creates a mock user agent for testing.
  """
  def mock_user_agent, do: "TestAgent/1.0"

  @doc """
  Verifies JWT token structure and claims.
  """
  def assert_valid_jwt(token) do
    assert is_binary(token)
    assert String.length(token) > 0

    case GuardianImpl.decode_and_verify(token) do
      {:ok, claims} ->
        assert claims["sub"]
        assert claims["exp"]
        assert claims["iat"]
        {:ok, claims}

      error ->
        flunk("Expected valid JWT token, got: #{inspect(error)}")
    end
  end

  @doc """
  Asserts that two tokens have different claims (for refresh scenarios).
  """
  def assert_different_tokens(token1, token2) do
    {:ok, claims1} = GuardianImpl.decode_and_verify(token1)
    {:ok, claims2} = GuardianImpl.decode_and_verify(token2)

    # At least the issued at time should be different
    refute claims1["iat"] == claims2["iat"]
  end

  # Private helpers

  defp unique_email do
    "user#{System.unique_integer([:positive])}@example.com"
  end

  defp unique_username do
    "user#{System.unique_integer([:positive])}"
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {key, value} when is_atom(key) -> {to_string(key), value}
      {key, value} -> {key, value}
    end)
  end

  defp stringify_keys(value), do: value
end
