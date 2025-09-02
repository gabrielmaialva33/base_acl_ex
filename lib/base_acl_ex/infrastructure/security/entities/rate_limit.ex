defmodule BaseAclEx.Infrastructure.Security.Entities.RateLimit do
  @moduledoc """
  Rate limit entity representing the current state of rate limiting for an identifier.
  """

  @type t :: %__MODULE__{
          identifier: String.t(),
          requests: [integer()],
          window_start: integer(),
          max_requests: integer(),
          window_ms: integer()
        }

  defstruct [
    :identifier,
    :requests,
    :window_start,
    :max_requests,
    :window_ms
  ]

  @doc """
  Returns the number of remaining requests in the current window.
  """
  def remaining_requests(%__MODULE__{} = rate_limit) do
    max(0, rate_limit.max_requests - length(rate_limit.requests))
  end

  @doc """
  Returns the time until the window resets (in seconds).
  """
  def reset_time(%__MODULE__{} = rate_limit) do
    case rate_limit.requests do
      [] ->
        0

      requests ->
        oldest_request = Enum.min(requests)
        reset_at = oldest_request + rate_limit.window_ms
        max(0, div(reset_at - System.system_time(:millisecond), 1000))
    end
  end

  @doc """
  Checks if the rate limit is currently exceeded.
  """
  def exceeded?(%__MODULE__{} = rate_limit) do
    length(rate_limit.requests) >= rate_limit.max_requests
  end

  @doc """
  Returns the current request count in the window.
  """
  def current_requests(%__MODULE__{} = rate_limit) do
    length(rate_limit.requests)
  end
end
