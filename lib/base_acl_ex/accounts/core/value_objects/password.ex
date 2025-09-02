defmodule BaseAclEx.Accounts.Core.ValueObjects.Password do
  @moduledoc """
  Password value object that handles password hashing, validation,
  and security policies.
  """
  
  use Ecto.Schema
  import Ecto.Changeset
  
  @primary_key false
  embedded_schema do
    field :hash, :string
    field :algorithm, :string, default: "argon2"
    field :last_changed_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :must_change, :boolean, default: false
  end
  
  @min_length 8
  @max_length 128
  @require_uppercase true
  @require_lowercase true
  @require_number true
  @require_special true
  @special_chars ~r/[!@#$%^&*(),.?":{}|<>]/
  
  @doc """
  Creates a new Password value object from a plain text password.
  """
  def new(plain_password) when is_binary(plain_password) do
    case validate_strength(plain_password) do
      :ok ->
        {:ok, %__MODULE__{
          hash: hash_password(plain_password),
          algorithm: "argon2",
          last_changed_at: DateTime.utc_now()
        }}
      {:error, reason} ->
        {:error, reason}
    end
  end
  
  def new(_), do: {:error, :invalid_password}
  
  @doc """
  Creates a Password value object from an already hashed password.
  """
  def from_hash(hash, opts \\ []) do
    %__MODULE__{
      hash: hash,
      algorithm: Keyword.get(opts, :algorithm, "argon2"),
      last_changed_at: Keyword.get(opts, :last_changed_at),
      expires_at: Keyword.get(opts, :expires_at),
      must_change: Keyword.get(opts, :must_change, false)
    }
  end
  
  @doc """
  Validates password strength according to security policies.
  """
  def validate_strength(password) when is_binary(password) do
    with :ok <- validate_length(password),
         :ok <- validate_complexity(password),
         :ok <- validate_common_patterns(password) do
      :ok
    end
  end
  
  def validate_strength(_), do: {:error, :invalid_password}
  
  defp validate_length(password) do
    len = String.length(password)
    
    cond do
      len < @min_length -> {:error, :password_too_short}
      len > @max_length -> {:error, :password_too_long}
      true -> :ok
    end
  end
  
  defp validate_complexity(password) do
    errors = []
    
    errors = if @require_uppercase && !String.match?(password, ~r/[A-Z]/), 
      do: [:missing_uppercase | errors], else: errors
    
    errors = if @require_lowercase && !String.match?(password, ~r/[a-z]/), 
      do: [:missing_lowercase | errors], else: errors
    
    errors = if @require_number && !String.match?(password, ~r/[0-9]/), 
      do: [:missing_number | errors], else: errors
    
    errors = if @require_special && !String.match?(password, @special_chars), 
      do: [:missing_special_char | errors], else: errors
    
    case errors do
      [] -> :ok
      _ -> {:error, {:weak_password, errors}}
    end
  end
  
  defp validate_common_patterns(password) do
    lower = String.downcase(password)
    
    common_passwords = [
      "password", "12345678", "qwerty", "abc123", "password123",
      "admin", "letmein", "welcome", "monkey", "dragon"
    ]
    
    if Enum.any?(common_passwords, &String.contains?(lower, &1)) do
      {:error, :common_password}
    else
      :ok
    end
  end
  
  @doc """
  Hashes a plain text password using Argon2.
  """
  def hash_password(plain_password) do
    Argon2.hash_pwd_salt(plain_password)
  end
  
  @doc """
  Verifies a plain text password against the hash.
  """
  def verify(%__MODULE__{hash: hash}, plain_password) when is_binary(plain_password) do
    Argon2.verify_pass(plain_password, hash)
  end
  
  def verify(_, _), do: false
  
  @doc """
  Checks if the password has expired.
  """
  def expired?(%__MODULE__{expires_at: nil}), do: false
  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
  
  @doc """
  Checks if the password must be changed.
  """
  def must_change?(%__MODULE__{must_change: must_change}), do: must_change
  
  @doc """
  Sets password expiration.
  """
  def set_expiration(%__MODULE__{} = password, days) when is_integer(days) and days > 0 do
    expires_at = DateTime.add(DateTime.utc_now(), days * 24 * 60 * 60, :second)
    %{password | expires_at: expires_at}
  end
  
  @doc """
  Marks password as requiring change.
  """
  def require_change(%__MODULE__{} = password) do
    %{password | must_change: true}
  end
end