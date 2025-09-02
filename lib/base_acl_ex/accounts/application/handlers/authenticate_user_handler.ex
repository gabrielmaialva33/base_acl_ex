defmodule BaseAclEx.Accounts.Application.Handlers.AuthenticateUserHandler do
  @moduledoc """
  Handler for user authentication command.
  Validates credentials and generates JWT tokens.
  """

  use BaseAclEx.SharedKernel.CQRS.CommandHandler

  alias BaseAclEx.Accounts.Application.Commands.AuthenticateUserCommand
  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Accounts.Core.ValueObjects.Password
  alias BaseAclEx.Identity.Application.Services.PermissionCache
  alias BaseAclEx.Infrastructure.Persistence.Repo
  alias BaseAclEx.Infrastructure.Security.JWT.GuardianImpl

  @impl true
  def execute(%AuthenticateUserCommand{} = command) do
    with {:ok, user} <- find_user_by_email(command.email),
         :ok <- verify_password(command.password, user.password_hash),
         :ok <- check_account_status(user),
         {:ok, tokens} <- generate_tokens(user, command),
         :ok <- warm_permission_cache(user),
         :ok <- record_login(user, command) do
      {:ok,
       %{
         user: user,
         tokens: tokens,
         domain_events: [
           create_user_authenticated_event(user, command)
         ]
       }}
    end
  end

  defp find_user_by_email(email) do
    case Repo.get_by(User, email: String.downcase(email)) do
      nil -> {:error, :invalid_credentials}
      user -> {:ok, user}
    end
  end

  defp verify_password(password, password_hash) do
    if Password.verify(password, password_hash) do
      :ok
    else
      {:error, :invalid_credentials}
    end
  end

  defp check_account_status(user) do
    cond do
      user.deleted_at != nil ->
        {:error, :account_deleted}

      user.locked_until != nil ->
        {:error, :account_locked}

      user.email_verified_at == nil ->
        {:error, :email_not_verified}

      true ->
        :ok
    end
  end

  defp generate_tokens(user, nil), do: GuardianImpl.generate_tokens(user)

  defp generate_tokens(user, command) do
    opts = build_token_options(command)
    GuardianImpl.generate_tokens_with_metadata(user, opts)
  end

  defp build_token_options(command) do
    [
      ip_address: command.ip_address,
      user_agent: command.user_agent,
      remember_me: Map.get(command, :remember_me, false),
      device_id: generate_device_id(command),
      device_name: parse_device_name(command.user_agent)
    ]
  end

  defp warm_permission_cache(user) do
    # Preload user permissions into cache
    permissions = load_user_permissions(user)
    PermissionCache.warm_user_cache(user.id, permissions)
    :ok
  end

  defp load_user_permissions(user) do
    # Load permissions from database
    # This would typically join through user_roles and role_permissions
    []
  end

  defp record_login(user, command) do
    attrs = %{
      last_login_at: DateTime.utc_now(),
      last_login_ip: command.ip_address,
      login_count: (user.login_count || 0) + 1
    }

    user
    |> Ecto.Changeset.change(attrs)
    |> Repo.update()

    :ok
  end

  defp create_user_authenticated_event(user, command) do
    %{
      type: "user_authenticated",
      aggregate_id: user.id,
      occurred_at: DateTime.utc_now(),
      payload: %{
        user_id: user.id,
        email: user.email,
        ip_address: command.ip_address,
        user_agent: command.user_agent
      }
    }
  end

  # Helper functions for device tracking

  defp generate_device_id(command) do
    # Generate a deterministic device ID based on user agent and IP
    # This helps identify unique devices for token management
    data = "#{command.user_agent}:#{command.ip_address}"

    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 16)
  end

  defp parse_device_name(user_agent) when is_binary(user_agent) do
    parse_device_from_agent(user_agent)
  end

  defp parse_device_from_agent(user_agent) do
    device_mappings = [
      {"Mobile", "Mobile Device"},
      {"iPhone", "iPhone"},
      {"Android", "Android Device"},
      {"iPad", "iPad"},
      {"Chrome", "Chrome Browser"},
      {"Firefox", "Firefox Browser"},
      {"Safari", "Safari Browser"},
      {"Edge", "Edge Browser"}
    ]

    device_mappings
    |> Enum.find(fn {pattern, _} -> String.contains?(user_agent, pattern) end)
    |> case do
      {_, device_name} -> device_name
      nil -> "Unknown Device"
    end
  end

  defp parse_device_name(_), do: "Unknown Device"
end
