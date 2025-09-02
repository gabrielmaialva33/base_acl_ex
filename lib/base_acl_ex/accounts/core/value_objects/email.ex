defmodule BaseAclEx.Accounts.Core.ValueObjects.Email do
  @moduledoc """
  Email value object that ensures email validity and provides
  email-related operations.
  """
  
  use Ecto.Schema
  import Ecto.Changeset
  
  @primary_key false
  embedded_schema do
    field :value, :string
    field :normalized, :string
    field :domain, :string
    field :verified, :boolean, default: false
    field :verified_at, :utc_datetime
  end
  
  @email_regex ~r/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  
  @doc """
  Creates a new Email value object from a string.
  """
  def new(email_string) when is_binary(email_string) do
    normalized = normalize(email_string)
    
    if valid?(normalized) do
      {:ok, %__MODULE__{
        value: email_string,
        normalized: normalized,
        domain: extract_domain(normalized),
        verified: false
      }}
    else
      {:error, :invalid_email}
    end
  end
  
  def new(_), do: {:error, :invalid_email}
  
  @doc """
  Creates a new Email value object, raising if invalid.
  """
  def new!(email_string) do
    case new(email_string) do
      {:ok, email} -> email
      {:error, reason} -> raise ArgumentError, "Invalid email: #{reason}"
    end
  end
  
  @doc """
  Validates if an email string is valid.
  """
  def valid?(email_string) when is_binary(email_string) do
    String.match?(email_string, @email_regex) && String.length(email_string) <= 254
  end
  
  def valid?(_), do: false
  
  @doc """
  Normalizes an email address (lowercase, trim).
  """
  def normalize(email_string) when is_binary(email_string) do
    email_string
    |> String.trim()
    |> String.downcase()
  end
  
  def normalize(_), do: ""
  
  @doc """
  Extracts the domain from an email address.
  """
  def extract_domain(email_string) when is_binary(email_string) do
    case String.split(email_string, "@") do
      [_, domain] -> domain
      _ -> nil
    end
  end
  
  def extract_domain(_), do: nil
  
  @doc """
  Marks the email as verified.
  """
  def mark_as_verified(%__MODULE__{} = email) do
    %{email | verified: true, verified_at: DateTime.utc_now()}
  end
  
  @doc """
  Checks if the email belongs to a specific domain.
  """
  def from_domain?(%__MODULE__{domain: domain}, check_domain) do
    domain == normalize(check_domain)
  end
  
  @doc """
  Returns the string representation of the email.
  """
  def to_string(%__MODULE__{value: value}), do: value
  
  defimpl String.Chars do
    def to_string(email), do: BaseAclEx.Accounts.Core.ValueObjects.Email.to_string(email)
  end
end