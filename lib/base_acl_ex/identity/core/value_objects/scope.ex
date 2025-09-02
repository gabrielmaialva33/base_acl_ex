defmodule BaseAclEx.Identity.Core.ValueObjects.Scope do
  @moduledoc """
  Scope value object representing the context or ownership level of a permission.
  Examples: "any", "own", "team", "department", "organization"
  """

  use Ecto.Schema

  @primary_key false
  embedded_schema do
    field :type, :string
    field :scope_id, :binary_id
    field :metadata, :map, default: %{}
  end

  @valid_scopes ~w(any own team department organization project global)
  @hierarchical_scopes ~w(own team department organization global)

  @doc """
  Creates a new Scope value object.
  """
  def new(type, scope_id \\ nil, metadata \\ %{})

  def new(type, scope_id, metadata) when is_binary(type) do
    normalized = normalize(type)

    if valid?(normalized) do
      {:ok,
       %__MODULE__{
         type: normalized,
         scope_id: scope_id,
         metadata: metadata
       }}
    else
      {:error, :invalid_scope}
    end
  end

  def new(_, _, _), do: {:error, :invalid_scope}

  @doc """
  Creates a global scope (access to all resources).
  """
  def global do
    {:ok, scope} = new("global")
    scope
  end

  @doc """
  Creates an 'any' scope (access to any resource of the type).
  """
  def any do
    {:ok, scope} = new("any")
    scope
  end

  @doc """
  Creates an 'own' scope (access only to owned resources).
  """
  def own do
    {:ok, scope} = new("own")
    scope
  end

  @doc """
  Creates a team scope.
  """
  def team(team_id) when is_binary(team_id) do
    {:ok, scope} = new("team", team_id)
    scope
  end

  @doc """
  Creates a department scope.
  """
  def department(department_id) when is_binary(department_id) do
    {:ok, scope} = new("department", department_id)
    scope
  end

  @doc """
  Creates an organization scope.
  """
  def organization(organization_id) when is_binary(organization_id) do
    {:ok, scope} = new("organization", organization_id)
    scope
  end

  @doc """
  Validates if a scope type is valid.
  """
  def valid?(type) when is_binary(type) do
    normalize(type) in @valid_scopes
  end

  def valid?(_), do: false

  @doc """
  Normalizes a scope type.
  """
  def normalize(type) when is_binary(type) do
    type
    |> String.trim()
    |> String.downcase()
  end

  def normalize(_), do: ""

  @doc """
  Checks if a scope is more permissive than another.
  Returns true if scope1 allows more access than scope2.
  """
  def more_permissive?(%__MODULE__{type: type1}, %__MODULE__{type: type2}) do
    hierarchy_level(type1) > hierarchy_level(type2)
  end

  @doc """
  Checks if a scope is less permissive than another.
  """
  def less_permissive?(%__MODULE__{type: type1}, %__MODULE__{type: type2}) do
    hierarchy_level(type1) < hierarchy_level(type2)
  end

  @doc """
  Checks if two scopes are equivalent.
  """
  def equivalent?(%__MODULE__{type: type1, scope_id: id1}, %__MODULE__{type: type2, scope_id: id2}) do
    type1 == type2 && id1 == id2
  end

  @doc """
  Checks if the scope requires ownership validation.
  """
  def requires_ownership?(%__MODULE__{type: "own"}), do: true
  def requires_ownership?(_), do: false

  @doc """
  Checks if the scope requires context validation (team, dept, org).
  """
  def requires_context?(%__MODULE__{type: type}) do
    type in ~w(team department organization project)
  end

  @doc """
  Returns the hierarchy level of a scope (higher = more permissive).
  """
  def hierarchy_level(type) when is_binary(type) do
    case normalize(type) do
      "global" -> 5
      "any" -> 4
      "organization" -> 3
      "department" -> 2
      "team" -> 1
      "own" -> 0
      _ -> -1
    end
  end

  def hierarchy_level(%__MODULE__{type: type}), do: hierarchy_level(type)

  @doc """
  Checks if a user scope satisfies a required scope.
  """
  def satisfies?(%__MODULE__{} = user_scope, %__MODULE__{} = required_scope) do
    cond do
      # Global scope satisfies everything
      user_scope.type == "global" ->
        true

      # Any scope satisfies everything except global
      user_scope.type == "any" && required_scope.type != "global" ->
        true

      # Same scope type with same ID
      user_scope.type == required_scope.type && user_scope.scope_id == required_scope.scope_id ->
        true

      # Higher level scope can satisfy lower level
      more_permissive?(user_scope, required_scope) ->
        true

      # Otherwise not satisfied
      true ->
        false
    end
  end

  @doc """
  Returns all valid scope types.
  """
  def all_scopes, do: @valid_scopes

  @doc """
  Returns hierarchical scope types.
  """
  def hierarchical_scopes, do: @hierarchical_scopes

  @doc """
  Returns the string representation.
  """
  def to_string(%__MODULE__{type: type, scope_id: nil}), do: type
  def to_string(%__MODULE__{type: type, scope_id: scope_id}), do: "#{type}:#{scope_id}"

  defimpl String.Chars do
    alias BaseAclEx.Identity.Core.ValueObjects.Scope

    def to_string(scope), do: Scope.to_string(scope)
  end
end
