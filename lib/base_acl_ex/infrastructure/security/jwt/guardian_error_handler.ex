defmodule BaseAclEx.Infrastructure.Security.JWT.GuardianErrorHandler do
  @moduledoc """
  Error handler for Guardian authentication failures.
  Returns proper HTTP status codes and error messages.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  @behaviour Guardian.Plug.ErrorHandler

  @impl Guardian.Plug.ErrorHandler
  def auth_error(conn, {type, reason}, _opts) do
    body = error_response(type, reason)

    conn
    |> put_status(status_code(type))
    |> put_resp_content_type("application/json")
    |> json(body)
  end

  defp error_response(type, reason) do
    %{
      error: %{
        type: to_string(type),
        reason: to_string(reason),
        message: error_message(type, reason),
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      }
    }
  end

  defp error_message(:invalid_token, _), do: "Invalid authentication token"
  defp error_message(:token_expired, _), do: "Authentication token has expired"
  defp error_message(:unauthenticated, _), do: "Authentication required"
  defp error_message(:unauthorized, _), do: "Insufficient permissions"
  defp error_message(:no_resource_found, _), do: "User not found"
  defp error_message(:already_authenticated, _), do: "Already authenticated"
  defp error_message(_, reason), do: "Authentication error: #{reason}"

  defp status_code(:invalid_token), do: 401
  defp status_code(:token_expired), do: 401
  defp status_code(:unauthenticated), do: 401
  defp status_code(:unauthorized), do: 403
  defp status_code(:no_resource_found), do: 404
  defp status_code(:already_authenticated), do: 400
  defp status_code(_), do: 401
end
