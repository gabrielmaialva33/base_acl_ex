defmodule BaseAclEx.Infrastructure.Security.Plugs.RateLimiter do
  @moduledoc """
  Rate limiting plug with configurable limits per endpoint type.

  Supports different rate limiting strategies and configurations:
  - IP-based limiting
  - User-based limiting  
  - Endpoint-specific limits
  - Admin bypass
  - Proper HTTP headers

  ## Usage

      # In router pipeline
      plug BaseAclEx.Infrastructure.Security.Plugs.RateLimiter, 
           max_requests: 100, 
           window_ms: 60_000,
           strategy: :ip
      
      # For auth endpoints
      plug BaseAclEx.Infrastructure.Security.Plugs.RateLimiter, :auth_limits
      
      # For general API endpoints  
      plug BaseAclEx.Infrastructure.Security.Plugs.RateLimiter, :api_limits
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias BaseAclEx.Infrastructure.Security.Services.RateLimiter
  alias BaseAclEx.Infrastructure.Security.Entities.RateLimit

  @presets %{
    auth_limits: [
      max_requests: 10,
      # 1 minute
      window_ms: 60_000,
      strategy: :ip,
      bypass_admin: true
    ],
    api_limits: [
      max_requests: 1000,
      # 1 minute  
      window_ms: 60_000,
      strategy: :user,
      bypass_admin: true
    ],
    strict_limits: [
      max_requests: 30,
      # 1 minute
      window_ms: 60_000,
      strategy: :ip_and_endpoint,
      bypass_admin: false
    ]
  }

  def init(opts) when is_atom(opts) do
    # Use preset configuration
    Map.get(@presets, opts, @presets.api_limits)
  end

  def init(opts) when is_list(opts) do
    # Custom configuration
    opts
  end

  def call(conn, opts) do
    # Check if rate limiting is disabled
    if Application.get_env(:base_acl_ex, :rate_limiting_enabled, true) do
      do_rate_limit(conn, opts)
    else
      conn
    end
  end

  defp do_rate_limit(conn, opts) do
    # Check admin bypass first
    if Keyword.get(opts, :bypass_admin, true) and RateLimiter.should_bypass?(conn) do
      add_bypass_headers(conn)
    else
      perform_rate_limiting(conn, opts)
    end
  end

  defp perform_rate_limiting(conn, opts) do
    identifier = RateLimiter.build_identifier(conn, opts)

    case RateLimiter.check_rate_limit(identifier, opts) do
      {:ok, rate_limit} ->
        conn
        |> add_rate_limit_headers(rate_limit)
        |> maybe_log_request(rate_limit, :allowed)

      {:error, rate_limit} ->
        conn
        |> add_rate_limit_headers(rate_limit)
        |> put_status(:too_many_requests)
        |> put_resp_content_type("application/json")
        |> json(%{
          error: %{
            message: "Rate limit exceeded. Try again later.",
            type: "rate_limit_exceeded",
            retry_after: RateLimit.reset_time(rate_limit)
          }
        })
        |> maybe_log_request(rate_limit, :blocked)
        |> halt()
    end
  end

  defp add_rate_limit_headers(conn, rate_limit) do
    conn
    |> put_resp_header("x-ratelimit-limit", to_string(rate_limit.max_requests))
    |> put_resp_header(
      "x-ratelimit-remaining",
      to_string(RateLimit.remaining_requests(rate_limit))
    )
    |> put_resp_header("x-ratelimit-reset", to_string(RateLimit.reset_time(rate_limit)))
    |> put_resp_header("x-ratelimit-window", to_string(div(rate_limit.window_ms, 1000)))
  end

  defp add_bypass_headers(conn) do
    conn
    |> put_resp_header("x-ratelimit-bypass", "admin")
    |> put_resp_header("x-ratelimit-limit", "unlimited")
    |> put_resp_header("x-ratelimit-remaining", "unlimited")
  end

  defp maybe_log_request(conn, rate_limit, status) do
    if Application.get_env(:base_acl_ex, :rate_limiting_log_enabled, false) do
      require Logger

      Logger.info("Rate limit #{status}", %{
        identifier: rate_limit.identifier,
        current_requests: RateLimit.current_requests(rate_limit),
        max_requests: rate_limit.max_requests,
        remaining: RateLimit.remaining_requests(rate_limit),
        endpoint: "#{conn.method} #{conn.request_path}",
        user_agent: get_req_header(conn, "user-agent") |> List.first()
      })
    end

    # Emit telemetry event for monitoring
    :telemetry.execute(
      [:base_acl_ex, :rate_limiter, status],
      %{
        requests: RateLimit.current_requests(rate_limit),
        remaining: RateLimit.remaining_requests(rate_limit)
      },
      %{
        identifier: rate_limit.identifier,
        endpoint: "#{conn.method} #{conn.request_path}",
        max_requests: rate_limit.max_requests,
        window_ms: rate_limit.window_ms
      }
    )

    conn
  end
end
