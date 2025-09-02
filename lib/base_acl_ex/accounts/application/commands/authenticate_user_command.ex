defmodule BaseAclEx.Accounts.Application.Commands.AuthenticateUserCommand do
  @moduledoc """
  Command to authenticate a user and generate JWT tokens.
  """
  
  use BaseAclEx.SharedKernel.CQRS.Command
  
  @enforce_keys [:email, :password]
  defstruct [
    :email,
    :password,
    :ip_address,
    :user_agent,
    :remember_me
  ]
  
  @doc """
  Creates a new authenticate user command.
  """
  def new(attrs) do
    %__MODULE__{
      email: attrs[:email],
      password: attrs[:password],
      ip_address: attrs[:ip_address],
      user_agent: attrs[:user_agent],
      remember_me: attrs[:remember_me] || false
    }
  end
  
  @impl true
  def validate(command) do
    errors = []
    
    errors = if is_nil(command.email) || command.email == "" do
      [{:email, "is required"} | errors]
    else
      errors
    end
    
    errors = if is_nil(command.password) || command.password == "" do
      [{:password, "is required"} | errors]
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
      command_type: "AuthenticateUser",
      email: command.email,
      ip_address: command.ip_address,
      user_agent: command.user_agent,
      timestamp: DateTime.utc_now()
    }
  end
end