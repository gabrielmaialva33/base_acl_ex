defmodule BaseAclEx.Identity.Core.Entities.Permission do
  @moduledoc """
  Permission entity representing a specific access right in the system.
  Follows the pattern: resource.action.context
  """

  use Ecto.Schema
  import Ecto.Changeset
  alias BaseAclEx.Identity.Core.ValueObjects.{Action, Resource, Scope}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]
  @derive {Jason.Encoder, except: [:__meta__]}

  schema "permissions" do
    field :name, :string
    field :resource, :string
    field :action, :string
    field :context, :string, default: "any"
    field :description, :string
    field :category, :string

    # Flags
    field :is_active, :boolean, default: true
    field :is_system, :boolean, default: false
    field :requires_ownership, :boolean, default: false
    field :requires_two_factor, :boolean, default: false

    # Risk and conditions
    field :risk_level, :string, default: "low"
    field :conditions, :map, default: %{}
    field :dependencies, {:array, :string}, default: []

    # Metadata
    field :metadata, :map, default: %{}

    # Virtual fields
    field :domain_events, {:array, :any}, virtual: true, default: []

    timestamps(type: :utc_datetime)
  end

  @required_fields [:resource, :action]
  @optional_fields [
    :name,
    :context,
    :description,
    :category,
    :is_active,
    :is_system,
    :requires_ownership,
    :requires_two_factor,
    :risk_level,
    :conditions,
    :dependencies,
    :metadata
  ]

  @doc """
  Creates a new permission.
  """
  def new(attrs) do
    %__MODULE__{}
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> generate_name()
    |> validate_resource()
    |> validate_action()
    |> validate_context()
    |> validate_risk_level()
    |> set_defaults()
    |> unique_constraint([:resource, :action, :context],
      name: :permissions_resource_action_context_unique
    )
  end

  @doc """
  Updates a permission.
  """
  def update(%__MODULE__{} = permission, attrs) do
    permission
    |> cast(attrs, [
      :description,
      :category,
      :is_active,
      :conditions,
      :dependencies,
      :metadata,
      :requires_two_factor
    ])
    |> validate_conditions()
  end

  @doc """
  Creates a permission from resource, action, and context strings.
  """
  def from_components(resource, action, context \\ "any") do
    new(%{
      resource: resource,
      action: action,
      context: context
    })
  end

  @doc """
  Parses a permission string (e.g., "users.create.any").
  """
  def from_string(permission_string) when is_binary(permission_string) do
    case String.split(permission_string, ".") do
      [resource, action] ->
        from_components(resource, action, "any")

      [resource, action, context] ->
        from_components(resource, action, context)

      _ ->
        {:error, :invalid_permission_format}
    end
  end

  @doc """
  Checks if the permission is a wildcard permission.
  """
  def wildcard?(%__MODULE__{action: "*"}), do: true
  def wildcard?(%__MODULE__{resource: "*"}), do: true
  def wildcard?(_), do: false

  @doc """
  Checks if the permission is for a system resource.
  """
  def system_permission?(%__MODULE__{resource: resource}) do
    resource in ~w(permissions roles users system audit_logs)
  end

  @doc """
  Checks if the permission is high risk.
  """
  def high_risk?(%__MODULE__{risk_level: risk_level}) do
    risk_level in ~w(high critical)
  end

  @doc """
  Checks if the permission requires ownership validation.
  """
  def requires_ownership?(%__MODULE__{context: "own"}), do: true
  def requires_ownership?(%__MODULE__{requires_ownership: true}), do: true
  def requires_ownership?(_), do: false

  @doc """
  Checks if a permission matches a pattern.
  """
  def matches?(%__MODULE__{} = permission, %__MODULE__{} = pattern) do
    resource_matches?(permission.resource, pattern.resource) &&
      action_matches?(permission.action, pattern.action) &&
      context_matches?(permission.context, pattern.context)
  end

  @doc """
  Returns the full permission name.
  """
  def full_name(%__MODULE__{resource: resource, action: action, context: context}) do
    "#{resource}.#{action}.#{context}"
  end

  @doc """
  Returns a display-friendly name.
  """
  def display_name(%__MODULE__{name: name}) when is_binary(name) and name != "", do: name
  def display_name(%__MODULE__{} = permission), do: full_name(permission)

  @doc """
  Activates the permission.
  """
  def activate(%__MODULE__{} = permission) do
    change(permission, %{is_active: true})
  end

  @doc """
  Deactivates the permission.
  """
  def deactivate(%__MODULE__{} = permission) do
    change(permission, %{is_active: false})
  end

  # Private functions

  defp generate_name(changeset) do
    resource = get_field(changeset, :resource)
    action = get_field(changeset, :action)
    context = get_field(changeset, :context) || "any"

    if resource && action do
      name = "#{resource}.#{action}.#{context}"
      put_change(changeset, :name, name)
    else
      changeset
    end
  end

  defp validate_resource(changeset) do
    validate_format(changeset, :resource, ~r/^[a-z][a-z0-9_]*$/,
      message: "must be lowercase alphanumeric with underscores"
    )
  end

  defp validate_action(changeset) do
    changeset
    |> validate_format(:action, ~r/^[a-z][a-z0-9_]*|\*$/,
      message: "must be lowercase alphanumeric with underscores or wildcard"
    )
    |> validate_action_for_resource()
  end

  defp validate_action_for_resource(changeset) do
    resource = get_field(changeset, :resource)
    action = get_field(changeset, :action)

    # Add any resource-specific action validation here
    changeset
  end

  defp validate_context(changeset) do
    validate_inclusion(
      changeset,
      :context,
      ~w(any own team department organization project global),
      message: "must be a valid context type"
    )
  end

  defp validate_risk_level(changeset) do
    validate_inclusion(changeset, :risk_level, ~w(low medium high critical),
      message: "must be a valid risk level"
    )
  end

  defp validate_conditions(changeset) do
    conditions = get_field(changeset, :conditions)

    if conditions && is_map(conditions) do
      changeset
    else
      add_error(changeset, :conditions, "must be a valid map")
    end
  end

  defp set_defaults(changeset) do
    changeset
    |> put_change_if_nil(:context, "any")
    |> put_change_if_nil(:risk_level, determine_risk_level(changeset))
    |> put_change_if_nil(:category, determine_category(changeset))
    |> put_change_if_nil(:requires_ownership, determine_ownership_requirement(changeset))
  end

  defp put_change_if_nil(changeset, field, value) do
    if get_field(changeset, field) == nil do
      put_change(changeset, field, value)
    else
      changeset
    end
  end

  defp determine_risk_level(changeset) do
    action = get_field(changeset, :action)
    resource = get_field(changeset, :resource)

    cond do
      action in ~w(delete destroy remove purge) -> "high"
      action in ~w(create update edit modify) -> "medium"
      resource in ~w(permissions roles system) -> "critical"
      action in ~w(read view list show) -> "low"
      true -> "low"
    end
  end

  defp determine_category(changeset) do
    resource = get_field(changeset, :resource)

    cond do
      resource in ~w(users roles permissions) -> "identity"
      resource in ~w(posts articles comments) -> "content"
      resource in ~w(files documents images) -> "storage"
      resource in ~w(reports analytics dashboard) -> "analytics"
      resource in ~w(settings system audit_logs) -> "system"
      true -> "general"
    end
  end

  defp determine_ownership_requirement(changeset) do
    get_field(changeset, :context) == "own"
  end

  defp resource_matches?(resource, pattern) do
    pattern == "*" || resource == pattern
  end

  defp action_matches?(action, pattern) do
    pattern == "*" || action == pattern
  end

  defp context_matches?(context, pattern) do
    pattern == "*" || context == pattern
  end
end
