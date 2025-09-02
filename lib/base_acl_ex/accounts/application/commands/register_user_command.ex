defmodule BaseAclEx.Accounts.Application.Commands.RegisterUserCommand do
  @moduledoc """
  Command to register a new user in the system.
  """

  use BaseAclEx.SharedKernel.CQRS.Command
  import Ecto.Changeset

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
    errors = []

    errors =
      if is_nil(command.email) || command.email == "" do
        [{:email, "is required"} | errors]
      else
        if valid_email?(command.email) do
          errors
        else
          [{:email, "is invalid"} | errors]
        end
      end

    errors =
      if is_nil(command.password) || String.length(command.password) < 8 do
        [{:password, "must be at least 8 characters"} | errors]
      else
        errors
      end

    errors =
      if is_nil(command.first_name) || command.first_name == "" do
        [{:first_name, "is required"} | errors]
      else
        errors
      end

    errors =
      if is_nil(command.last_name) || command.last_name == "" do
        [{:last_name, "is required"} | errors]
      else
        errors
      end

    errors =
      if command.terms_accepted != true do
        [{:terms_accepted, "must be accepted"} | errors]
      else
        errors
      end

    if Enum.empty?(errors) do
      {:ok, command}
    else
      {:error, errors}
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
