defmodule BaseAclExWeb.Api.V1.RateLimiterController do
  @moduledoc """
  Administrative API for managing rate limiting system.

  Provides endpoints for monitoring, configuring, and managing rate limits.
  Requires admin privileges for all operations.
  """

  use BaseAclExWeb, :controller

  alias BaseAclEx.Infrastructure.Security.Services.RateLimiterManager
  alias BaseAclEx.Infrastructure.Security.Services.RateLimiter

  action_fallback BaseAclExWeb.FallbackController

  @doc """
  GET /api/v1/admin/rate-limiter/stats

  Returns comprehensive statistics about the rate limiting system.
  """
  def stats(conn, _params) do
    stats = RateLimiterManager.get_system_stats()

    conn
    |> put_status(:ok)
    |> json(%{
      data: stats,
      message: "Rate limiter statistics retrieved successfully"
    })
  end

  @doc """
  GET /api/v1/admin/rate-limiter/limits

  Lists active rate limits with pagination and filtering.

  Query parameters:
  - limit: Maximum entries to return (default: 100)
  - sort_by: requests|remaining|identifier (default: requests)
  - pattern: Filter by identifier pattern
  - blocked_only: Show only exceeded limits (boolean)
  """
  def list_limits(conn, params) do
    opts = [
      limit: Map.get(params, "limit", "100") |> String.to_integer(),
      sort_by: Map.get(params, "sort_by", "requests") |> String.to_existing_atom()
    ]

    limits =
      cond do
        Map.get(params, "blocked_only") == "true" ->
          RateLimiterManager.get_blocked_identifiers()

        pattern = Map.get(params, "pattern") ->
          RateLimiterManager.find_limits_by_pattern(pattern)

        true ->
          RateLimiterManager.list_active_limits(opts)
      end

    conn
    |> put_status(:ok)
    |> json(%{
      data: %{
        limits: limits,
        total: length(limits),
        filters: Map.take(params, ["pattern", "blocked_only", "sort_by"])
      },
      message: "Rate limits retrieved successfully"
    })
  end

  @doc """
  GET /api/v1/admin/rate-limiter/limits/:identifier

  Gets detailed information about a specific rate limit.
  """
  def show_limit(conn, %{"identifier" => identifier}) do
    case RateLimiterManager.get_limit_details(identifier) do
      {:ok, limit_details} ->
        conn
        |> put_status(:ok)
        |> json(%{
          data: limit_details,
          message: "Rate limit details retrieved successfully"
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{
          error: %{
            message: "Rate limit not found for identifier: #{identifier}",
            type: "not_found"
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: %{
            message: "Failed to retrieve rate limit details",
            type: "internal_error",
            details: inspect(reason)
          }
        })
    end
  end

  @doc """
  DELETE /api/v1/admin/rate-limiter/limits/:identifier

  Removes rate limit for specific identifier.
  """
  def remove_limit(conn, %{"identifier" => identifier}) do
    RateLimiterManager.remove_limit(identifier)

    conn
    |> put_status(:ok)
    |> json(%{
      message: "Rate limit removed successfully for #{identifier}"
    })
  end

  @doc """
  DELETE /api/v1/admin/rate-limiter/limits

  Clears all rate limits (emergency operation).
  Requires confirmation parameter.
  """
  def clear_all_limits(conn, %{"confirm" => "yes"}) do
    RateLimiterManager.clear_all_limits()

    conn
    |> put_status(:ok)
    |> json(%{
      message: "All rate limits cleared successfully"
    })
  end

  def clear_all_limits(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      error: %{
        message: "Confirmation required. Add ?confirm=yes to proceed.",
        type: "confirmation_required"
      }
    })
  end

  @doc """
  GET /api/v1/admin/rate-limiter/export

  Exports rate limiting data for analysis.

  Query parameters:
  - format: json|csv (default: json)
  """
  def export_data(conn, params) do
    format =
      case Map.get(params, "format", "json") do
        "csv" -> :csv
        _ -> :json
      end

    data = RateLimiterManager.export_data(format)

    content_type =
      case format do
        :csv -> "text/csv"
        :json -> "application/json"
      end

    filename =
      case format do
        :csv -> "rate_limits_#{Date.utc_today()}.csv"
        :json -> "rate_limits_#{Date.utc_today()}.json"
      end

    conn
    |> put_resp_content_type(content_type)
    |> put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
    |> send_resp(:ok, data)
  end

  @doc """
  POST /api/v1/admin/rate-limiter/test

  Tests rate limiting for a given identifier without affecting real limits.
  """
  def test_limit(conn, %{"identifier" => identifier} = params) do
    opts = [
      max_requests: Map.get(params, "max_requests", 60) |> ensure_integer(),
      window_ms: Map.get(params, "window_ms", 60_000) |> ensure_integer()
    ]

    current_status = RateLimiter.get_rate_limit_status(identifier, opts)

    conn
    |> put_status(:ok)
    |> json(%{
      data: %{
        identifier: identifier,
        current_requests: BaseAclEx.Infrastructure.Security.Entities.RateLimit.current_requests(current_status),
        max_requests: current_status.max_requests,
        remaining: BaseAclEx.Infrastructure.Security.Entities.RateLimit.remaining_requests(current_status),
        exceeded: BaseAclEx.Infrastructure.Security.Entities.RateLimit.exceeded?(current_status),
        reset_time: BaseAclEx.Infrastructure.Security.Entities.RateLimit.reset_time(current_status),
        window_ms: current_status.window_ms
      },
      message: "Rate limit test completed"
    })
  end

  def test_limit(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      error: %{
        message: "identifier parameter is required",
        type: "missing_parameter"
      }
    })
  end

  # Private functions

  defp ensure_integer(value) when is_integer(value), do: value

  defp ensure_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> 0
    end
  end

  defp ensure_integer(_), do: 0
end
