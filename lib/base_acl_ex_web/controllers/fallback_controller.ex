defmodule BaseAclExWeb.FallbackController do
  @moduledoc """
  Fallback controller for handling errors in API responses.
  Translates controller action results into appropriate HTTP responses.
  """

  use BaseAclExWeb, :controller

  # Handle Ecto.Changeset errors
  def call(conn, {:error, %Ecto.Changeset{} = changeset}) do
    conn
    |> put_status(:unprocessable_entity)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, changeset: changeset)
  end

  # Handle not found errors
  def call(conn, {:error, :not_found}) do
    conn
    |> put_status(:not_found)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Resource not found")
  end

  def call(conn, {:error, :user_not_found}) do
    conn
    |> put_status(:not_found)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "User not found")
  end

  # Handle authentication errors
  def call(conn, {:error, :invalid_credentials}) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Invalid email or password")
  end

  def call(conn, {:error, :token_expired}) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Token has expired")
  end

  def call(conn, {:error, :invalid_token}) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Invalid token")
  end

  def call(conn, {:error, :unauthenticated}) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Authentication required")
  end

  # Handle authorization errors
  def call(conn, {:error, :unauthorized}) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "You don't have permission to perform this action")
  end

  def call(conn, {:error, :insufficient_permissions}) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Insufficient permissions")
  end

  # Handle account status errors
  def call(conn, {:error, :account_locked}) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Account is locked")
  end

  def call(conn, {:error, :account_deleted}) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Account has been deleted")
  end

  def call(conn, {:error, :email_not_verified}) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "Email address not verified")
  end

  # Handle validation errors
  def call(conn, {:error, errors}) when is_list(errors) do
    conn
    |> put_status(:unprocessable_entity)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:validation_errors, errors: errors)
  end

  # Handle generic errors
  def call(conn, {:error, message}) when is_binary(message) do
    conn
    |> put_status(:bad_request)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: message)
  end

  def call(conn, {:error, atom}) when is_atom(atom) do
    message = atom |> to_string() |> String.replace("_", " ") |> String.capitalize()

    conn
    |> put_status(:bad_request)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: message)
  end

  # Catch-all for unexpected errors
  def call(conn, _error) do
    conn
    |> put_status(:internal_server_error)
    |> put_view(json: BaseAclExWeb.ErrorJSON)
    |> render(:error, message: "An unexpected error occurred")
  end
end
