defmodule BaseAclEx.Accounts.Application.Commands.RegisterUserCommand do
  @moduledoc """
  Command to register a new user in the system.
  """

  use BaseAclEx.SharedKernel.CQRS.Command

  @enforce_keys [:email, :password, :first_name, :last_name]
  defstruct [
    :email,
    :password,
    :first_name,
    :last_name,
    :username,
    :phone_number,
    :terms_accepted,
    :newsletter_opt_in
  ]

  @doc """
  Creates a new register user command with validation.
  """
  def new(attrs) do
    %__MODULE__{
      email: attrs[:email],
      password: attrs[:password],
      first_name: attrs[:first_name],
      last_name: attrs[:last_name],
      username: attrs[:username],
      phone_number: attrs[:phone_number],
      terms_accepted: attrs[:terms_accepted] || false,
      newsletter_opt_in: attrs[:newsletter_opt_in] || false
    }
  end

  @impl true
  def validate(command) do
    validators = [
      &validate_email/1,
      &validate_password/1,
      &validate_first_name/1,
      &validate_last_name/1,
      &validate_terms/1
    ]

    errors =
      validators
      |> Enum.map(fn validator -> validator.(command) end)
      |> Enum.filter(fn result -> result != :ok end)
      |> Enum.map(fn {:error, error} -> error end)

    if Enum.empty?(errors) do
      {:ok, command}
    else
      {:error, errors}
    end
  end

  defp validate_email(command) do
    cond do
      is_nil(command.email) || command.email == "" ->
        {:error, {:email, "is required"}}

      !valid_email?(command.email) ->
        {:error, {:email, "is invalid"}}

      true ->
        :ok
    end
  end

  defp validate_password(command) do
    if is_nil(command.password) || String.length(command.password) < 8 do
      {:error, {:password, "must be at least 8 characters"}}
    else
      :ok
    end
  end

  defp validate_first_name(command) do
    if is_nil(command.first_name) || command.first_name == "" do
      {:error, {:first_name, "is required"}}
    else
      :ok
    end
  end

  defp validate_last_name(command) do
    if is_nil(command.last_name) || command.last_name == "" do
      {:error, {:last_name, "is required"}}
    else
      :ok
    end
  end

  defp validate_terms(command) do
    if command.terms_accepted != true do
      {:error, {:terms_accepted, "must be accepted"}}
    else
      :ok
    end
  end

  @impl true
  def metadata(command) do
    %{
      command_type: "RegisterUser",
      email: command.email,
      timestamp: DateTime.utc_now(),
      # To be set by the handler
      ip_address: nil
    }
  end

  defp valid_email?(email) do
    String.match?(email, ~r/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/)
  end
end
