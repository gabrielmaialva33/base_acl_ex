defmodule BaseAclEx.Infrastructure.Security.Services.RateLimiter do
  @moduledoc """
  Rate limiting service using sliding window algorithm with Cachex backend.

  Provides flexible rate limiting with support for:
  - IP-based and user-based limiting
  - Different limits for different endpoints
  - Sliding window algorithm for accuracy
  - Admin bypass capability
  - Proper rate limit headers
  """

  alias BaseAclEx.Infrastructure.Security.Entities.RateLimit

  @cache_name :rate_limiter_cache
  # 1 minute
  @default_window_ms 60_000
  @default_max_requests 60

  @doc """
  Checks if a request should be rate limited.

  Returns:
  - `{:ok, rate_limit}` - Request allowed, returns current state
  - `{:error, rate_limit}` - Request denied, returns limit info
  """
  def check_rate_limit(identifier, opts \\ []) do
    max_requests = Keyword.get(opts, :max_requests, @default_max_requests)
    window_ms = Keyword.get(opts, :window_ms, @default_window_ms)

    now = System.system_time(:millisecond)
    window_start = now - window_ms

    # Get or initialize counter
    case Cachex.get(@cache_name, identifier) do
      {:ok, nil} ->
        # First request
        rate_limit = %RateLimit{
          identifier: identifier,
          requests: [now],
          window_start: window_start,
          max_requests: max_requests,
          window_ms: window_ms
        }

        Cachex.put(@cache_name, identifier, rate_limit, ttl: window_ms)
        {:ok, rate_limit}

      {:ok, rate_limit} ->
        # Clean old requests outside the window
        valid_requests = Enum.filter(rate_limit.requests, &(&1 > window_start))

        if length(valid_requests) >= max_requests do
          # Rate limit exceeded
          updated_rate_limit = %{
            rate_limit
            | requests: valid_requests,
              window_start: window_start
          }

          Cachex.put(@cache_name, identifier, updated_rate_limit, ttl: window_ms)
          {:error, updated_rate_limit}
        else
          # Request allowed
          updated_requests = [now | valid_requests]

          updated_rate_limit = %{
            rate_limit
            | requests: updated_requests,
              window_start: window_start
          }

          Cachex.put(@cache_name, identifier, updated_rate_limit, ttl: window_ms)
          {:ok, updated_rate_limit}
        end

      {:error, _reason} ->
        # Cache error, allow request but log
        require Logger
        Logger.warning("Rate limiter cache error for #{identifier}")

        rate_limit = %RateLimit{
          identifier: identifier,
          requests: [now],
          window_start: window_start,
          max_requests: max_requests,
          window_ms: window_ms
        }

        {:ok, rate_limit}
    end
  end

  @doc """
  Resets rate limit for a specific identifier.
  Useful for admin operations or clearing blocks.
  """
  def reset_rate_limit(identifier) do
    Cachex.del(@cache_name, identifier)
  end

  @doc """
  Gets current rate limit status without incrementing counter.
  """
  def get_rate_limit_status(identifier, opts \\ []) do
    max_requests = Keyword.get(opts, :max_requests, @default_max_requests)
    window_ms = Keyword.get(opts, :window_ms, @default_window_ms)

    now = System.system_time(:millisecond)
    window_start = now - window_ms

    case Cachex.get(@cache_name, identifier) do
      {:ok, nil} ->
        %RateLimit{
          identifier: identifier,
          requests: [],
          window_start: window_start,
          max_requests: max_requests,
          window_ms: window_ms
        }

      {:ok, rate_limit} ->
        valid_requests = Enum.filter(rate_limit.requests, &(&1 > window_start))

        %{rate_limit | requests: valid_requests, window_start: window_start}

      {:error, _reason} ->
        %RateLimit{
          identifier: identifier,
          requests: [],
          window_start: window_start,
          max_requests: max_requests,
          window_ms: window_ms
        }
    end
  end

  @doc """
  Builds rate limit identifier from connection and options.
  """
  def build_identifier(conn, opts \\ []) do
    strategy = Keyword.get(opts, :strategy, :ip)

    case strategy do
      :ip ->
        get_client_ip(conn)

      :user ->
        case Guardian.Plug.current_resource(conn) do
          # Fallback to IP for unauthenticated users
          nil -> get_client_ip(conn)
          user -> "user:#{user.id}"
        end

      :ip_and_endpoint ->
        ip = get_client_ip(conn)
        endpoint = "#{conn.method}:#{conn.request_path}"
        "#{ip}:#{endpoint}"

      :user_and_endpoint ->
        endpoint = "#{conn.method}:#{conn.request_path}"

        case Guardian.Plug.current_resource(conn) do
          nil -> "#{get_client_ip(conn)}:#{endpoint}"
          user -> "user:#{user.id}:#{endpoint}"
        end
    end
  end

  @doc """
  Checks if user should bypass rate limiting (admin users).
  """
  def should_bypass?(conn) do
    case Guardian.Plug.current_resource(conn) do
      nil ->
        false

      user ->
        # Check if user has admin role or bypass permission
        has_admin_role?(user) or has_bypass_permission?(user)
    end
  end

  # Private functions

  defp get_client_ip(conn) do
    # Handle various proxy headers for real IP
    forwarded_for = get_req_header(conn, "x-forwarded-for") |> List.first()
    real_ip = get_req_header(conn, "x-real-ip") |> List.first()

    cond do
      forwarded_for && forwarded_for != "" ->
        forwarded_for |> String.split(",") |> List.first() |> String.trim()

      real_ip && real_ip != "" ->
        real_ip

      true ->
        conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp has_admin_role?(user) do
    # This will integrate with your existing role system
    # For now, we'll check if user has 'admin' role
    case user do
      %{roles: roles} when is_list(roles) ->
        Enum.any?(roles, &(&1.name == "admin"))

      _ ->
        false
    end
  end

  defp has_bypass_permission?(user) do
    # Check for specific bypass permission
    case user do
      %{permissions: permissions} when is_list(permissions) ->
        Enum.any?(permissions, &(&1.name == "rate_limit_bypass"))

      _ ->
        false
    end
  end

  defp get_req_header(conn, header) do
    Plug.Conn.get_req_header(conn, header)
  end
end
