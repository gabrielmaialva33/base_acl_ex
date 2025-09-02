defmodule BaseAclEx.Accounts.Application.Handlers.RegisterUserHandler do
  @moduledoc """
  Handler for user registration command.
  Creates a new user account with default role.
  """
  
  use BaseAclEx.SharedKernel.CQRS.CommandHandler
  
  alias BaseAclEx.Accounts.Core.Entities.User
  alias BaseAclEx.Accounts.Core.ValueObjects.{Email, Password}
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.Infrastructure.Persistence.Repo
  alias BaseAclEx.Accounts.Application.Commands.RegisterUserCommand
  
  @impl true
  def execute(%RegisterUserCommand{} = command) do
    with {:ok, email} <- Email.new(command.email),
         {:ok, password} <- Password.new(command.password),
         {:ok, user} <- create_user(command, email, password),
         {:ok, user} <- assign_default_role(user),
         :ok <- send_welcome_email(user) do
      
      {:ok, %{
        user: user,
        domain_events: [
          create_user_registered_event(user)
        ]
      }}
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, format_changeset_errors(changeset)}
      
      error ->
        error
    end
  end
  
  defp create_user(command, email, password) do
    attrs = %{
      email: Email.value(email),
      password_hash: Password.hash(password),
      first_name: command.first_name,
      last_name: command.last_name,
      username: command.username || generate_username(command),
      phone_number: command.phone_number,
      newsletter_opt_in: command.newsletter_opt_in,
      terms_accepted_at: if(command.terms_accepted, do: DateTime.utc_now(), else: nil)
    }
    
    %User{}
    |> User.registration_changeset(attrs)
    |> Repo.insert()
  end
  
  defp assign_default_role(user) do
    # Assign "user" role by default
    case Repo.get_by(Role, slug: "user") do
      nil ->
        # Create default role if it doesn't exist
        {:ok, role} = %Role{}
                      |> Role.create_system_role("user")
                      |> Repo.insert()
        
        assign_role_to_user(user, role)
      
      role ->
        assign_role_to_user(user, role)
    end
  end
  
  defp assign_role_to_user(user, role) do
    # This would typically use a join table
    # For now, we'll just return the user
    {:ok, user}
  end
  
  defp send_welcome_email(user) do
    # Send welcome email via mailer
    # BaseAclEx.Mailer.deliver_welcome_email(user)
    :ok
  end
  
  defp generate_username(command) do
    base = String.downcase("#{command.first_name}.#{command.last_name}")
    |> String.replace(~r/[^a-z0-9.]/, "")
    
    # Add random suffix if needed
    "#{base}.#{:rand.uniform(9999)}"
  end
  
  defp create_user_registered_event(user) do
    %{
      type: "user_registered",
      aggregate_id: user.id,
      occurred_at: DateTime.utc_now(),
      payload: %{
        user_id: user.id,
        email: user.email,
        username: user.username
      }
    }
  end
  
  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end