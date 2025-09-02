defmodule BaseAclEx.Identity.Core.ValueObjects.Action do
  @moduledoc """
  Action value object representing an operation that can be performed on a resource.
  Examples: "create", "read", "update", "delete", "execute"
  """
  
  use Ecto.Schema
  import Ecto.Changeset
  
  @primary_key false
  embedded_schema do
    field :name, :string
    field :type, :string
    field :risk_level, :string
  end
  
  @valid_actions ~w(
    create read update delete
    list view show index
    execute run process
    import export download upload
    approve reject publish unpublish
    activate deactivate enable disable
    grant revoke assign unassign
    login logout register
    search filter sort
    print email share
    backup restore migrate
    audit log monitor
  )
  
  @crud_actions ~w(create read update delete)
  @read_actions ~w(read list view show index search filter sort)
  @write_actions ~w(create update delete import upload)
  @admin_actions ~w(grant revoke backup restore migrate audit)
  
  @doc """
  Creates a new Action value object.
  """
  def new(name) when is_binary(name) do
    normalized = normalize(name)
    
    if valid?(normalized) do
      {:ok, %__MODULE__{
        name: normalized,
        type: categorize_type(normalized),
        risk_level: assess_risk(normalized)
      }}
    else
      {:error, :invalid_action}
    end
  end
  
  def new(_), do: {:error, :invalid_action}
  
  @doc """
  Creates a new Action, raising if invalid.
  """
  def new!(name) do
    case new(name) do
      {:ok, action} -> action
      {:error, reason} -> raise ArgumentError, "Invalid action: #{reason}"
    end
  end
  
  @doc """
  Validates if an action name is valid.
  """
  def valid?(name) when is_binary(name) do
    normalize(name) in @valid_actions || custom_action_valid?(name)
  end
  
  def valid?(_), do: false
  
  @doc """
  Normalizes an action name.
  """
  def normalize(name) when is_binary(name) do
    name
    |> String.trim()
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9_]/, "_")
  end
  
  def normalize(_), do: ""
  
  @doc """
  Categorizes the type of action.
  """
  def categorize_type(name) when is_binary(name) do
    normalized = normalize(name)
    
    cond do
      normalized in @crud_actions -> "crud"
      normalized in @read_actions -> "read"
      normalized in @write_actions -> "write"
      normalized in @admin_actions -> "admin"
      true -> "custom"
    end
  end
  
  def categorize_type(_), do: "unknown"
  
  @doc """
  Assesses the risk level of an action.
  """
  def assess_risk(name) when is_binary(name) do
    normalized = normalize(name)
    
    cond do
      normalized in @read_actions -> "low"
      normalized in ~w(update edit modify) -> "medium"
      normalized in ~w(delete remove destroy) -> "high"
      normalized in @admin_actions -> "critical"
      normalized in ~w(create add insert) -> "medium"
      true -> "low"
    end
  end
  
  def assess_risk(_), do: "unknown"
  
  @doc """
  Checks if the action is read-only.
  """
  def read_only?(name) do
    normalize(name) in @read_actions
  end
  
  @doc """
  Checks if the action modifies data.
  """
  def modifies_data?(name) do
    normalize(name) in @write_actions
  end
  
  @doc """
  Checks if the action is administrative.
  """
  def administrative?(name) do
    normalize(name) in @admin_actions
  end
  
  @doc """
  Returns all valid actions.
  """
  def all_actions, do: @valid_actions
  
  @doc """
  Returns CRUD actions.
  """
  def crud_actions, do: @crud_actions
  
  @doc """
  Returns the string representation.
  """
  def to_string(%__MODULE__{name: name}), do: name
  
  # Allow custom actions with specific pattern
  defp custom_action_valid?(name) do
    String.match?(name, ~r/^[a-z][a-z0-9_]{1,29}$/)
  end
  
  defimpl String.Chars do
    def to_string(action), do: BaseAclEx.Identity.Core.ValueObjects.Action.to_string(action)
  end
end