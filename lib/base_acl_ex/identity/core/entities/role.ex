defmodule BaseAclEx.Identity.Core.Entities.Role do
  @moduledoc """
  Role entity representing a collection of permissions that can be assigned to users.
  Supports role hierarchy where parent roles inherit permissions from child roles.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]
  @derive {Jason.Encoder, except: [:__meta__, :parent_role]}

  schema "roles" do
    field :name, :string
    field :slug, :string
    field :description, :string

    # Hierarchy
    field :hierarchy_level, :integer
    belongs_to :parent_role, __MODULE__, foreign_key: :parent_role_id

    # Flags
    field :is_active, :boolean, default: true
    field :is_system, :boolean, default: false

    # UI/UX
    field :color, :string
    field :icon, :string

    # Constraints
    field :max_users, :integer
    field :features, {:array, :string}, default: []

    # Metadata
    field :metadata, :map, default: %{}

    # Associations (to be defined in infrastructure layer)
    # many_to_many :permissions, Permission, join_through: "role_permissions"
    # many_to_many :users, User, join_through: "user_roles"

    # Virtual fields
    field :domain_events, {:array, :any}, virtual: true, default: []
    field :permission_count, :integer, virtual: true
    field :user_count, :integer, virtual: true

    timestamps(type: :utc_datetime)
  end

  # Predefined system roles with hierarchy levels
  @system_roles %{
    "root" => %{level: 100, name: "Root Administrator", system: true},
    "admin" => %{level: 90, name: "Administrator", system: true},
    "manager" => %{level: 70, name: "Manager", system: true},
    "editor" => %{level: 50, name: "Editor", system: true},
    "user" => %{level: 30, name: "User", system: true},
    "guest" => %{level: 10, name: "Guest", system: true}
  }

  @required_fields [:name, :slug, :hierarchy_level]
  @optional_fields [
    :description,
    :parent_role_id,
    :is_active,
    :is_system,
    :color,
    :icon,
    :max_users,
    :features,
    :metadata
  ]

  @doc """
  Creates a new role.
  """
  def new(attrs) do
    %__MODULE__{}
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> generate_slug()
    |> validate_slug()
    |> validate_name()
    |> validate_hierarchy_level()
    |> validate_parent_role()
    |> set_system_role_defaults()
    |> unique_constraint(:slug, name: :roles_slug_unique)
    |> unique_constraint(:name, name: :roles_name_unique)
  end

  @doc """
  Updates a role.
  """
  def update(%__MODULE__{is_system: true} = role, _attrs) do
    role
    |> change()
    |> add_error(:base, "system roles cannot be modified")
  end

  def update(%__MODULE__{} = role, attrs) do
    role
    |> cast(attrs, [
      :name,
      :description,
      :is_active,
      :color,
      :icon,
      :max_users,
      :features,
      :metadata
    ])
    |> validate_name()
    |> validate_max_users()
  end

  @doc """
  Generic changeset function for controllers.
  """
  def changeset(role_or_struct \\ %__MODULE__{}, attrs) do
    case role_or_struct do
      %__MODULE__{id: nil} -> new(attrs)
      %__MODULE__{} -> update(role_or_struct, attrs)
      _ -> new(attrs)
    end
  end

  @doc """
  Creates a system role.
  """
  def create_system_role(attrs, slug) when is_map(attrs) and is_binary(slug) do
    attrs
    |> Map.put(:slug, slug)
    |> Map.put(:is_system, true)
    |> Map.put(:is_active, true)
    |> new()
  end

  def create_system_role(slug) when is_binary(slug) do
    case Map.get(@system_roles, slug) do
      nil ->
        {:error, :unknown_system_role}

      config ->
        new(%{
          name: config.name,
          slug: slug,
          hierarchy_level: config.level,
          is_system: true,
          is_active: true
        })
    end
  end

  @doc """
  Checks if a role is higher in hierarchy than another.
  """
  def higher_than?(%__MODULE__{hierarchy_level: level1}, %__MODULE__{hierarchy_level: level2}) do
    level1 > level2
  end

  @doc """
  Checks if a role is lower in hierarchy than another.
  """
  def lower_than?(%__MODULE__{hierarchy_level: level1}, %__MODULE__{hierarchy_level: level2}) do
    level1 < level2
  end

  @doc """
  Checks if a role is at the same level as another.
  """
  def same_level?(%__MODULE__{hierarchy_level: level1}, %__MODULE__{hierarchy_level: level2}) do
    level1 == level2
  end

  @doc """
  Checks if the role is a system role.
  """
  def system_role?(%__MODULE__{is_system: is_system}), do: is_system

  @doc """
  Checks if the role is active.
  """
  def active?(%__MODULE__{is_active: is_active}), do: is_active

  @doc """
  Checks if the role has reached its user limit.
  """
  def at_user_limit?(%__MODULE__{max_users: nil}, _current_count), do: false

  def at_user_limit?(%__MODULE__{max_users: max}, current_count) when is_integer(current_count) do
    current_count >= max
  end

  @doc """
  Checks if a role can be assigned to users.
  """
  def assignable?(%__MODULE__{} = role) do
    role.is_active && !at_user_limit?(role, role.user_count || 0)
  end

  @doc """
  Checks if a role has a specific feature enabled.
  """
  def has_feature?(%__MODULE__{features: features}, feature) when is_binary(feature) do
    feature in (features || [])
  end

  @doc """
  Activates the role.
  """
  def activate(%__MODULE__{} = role) do
    change(role, %{is_active: true})
  end

  @doc """
  Deactivates the role.
  """
  def deactivate(%__MODULE__{} = role) do
    change(role, %{is_active: false})
  end

  @doc """
  Sets the parent role.
  """
  def set_parent(%__MODULE__{} = role, %__MODULE__{id: parent_id, hierarchy_level: parent_level}) do
    if role.hierarchy_level < parent_level do
      change(role, %{parent_role_id: parent_id})
    else
      role
      |> change()
      |> add_error(:parent_role_id, "parent role must have higher hierarchy level")
    end
  end

  @doc """
  Returns all system role slugs.
  """
  def system_role_slugs, do: Map.keys(@system_roles)

  @doc """
  Returns the display name for the role.
  """
  def display_name(%__MODULE__{name: name}), do: name

  # Private functions

  defp generate_slug(changeset) do
    case get_change(changeset, :slug) do
      nil ->
        name = get_field(changeset, :name)

        if name do
          slug =
            name
            |> String.downcase()
            |> String.replace(~r/[^a-z0-9]+/, "_")
            |> String.trim("_")

          put_change(changeset, :slug, slug)
        else
          changeset
        end

      _ ->
        changeset
    end
  end

  defp validate_slug(changeset) do
    validate_format(changeset, :slug, ~r/^[a-z][a-z0-9_]*$/,
      message:
        "must start with letter and contain only lowercase letters, numbers and underscores"
    )
  end

  defp validate_name(changeset) do
    changeset
    |> validate_length(:name, min: 2, max: 100)
    |> validate_format(:name, ~r/^[A-Za-z]/, message: "must start with a letter")
  end

  defp validate_hierarchy_level(changeset) do
    changeset
    |> validate_number(:hierarchy_level, greater_than_or_equal_to: 0, less_than_or_equal_to: 1000)
  end

  defp validate_parent_role(changeset) do
    parent_id = get_change(changeset, :parent_role_id)
    hierarchy_level = get_field(changeset, :hierarchy_level)

    if parent_id && hierarchy_level do
      # In a real implementation, we would check the parent's hierarchy level
      # For now, we just ensure it's not self-referential
      if parent_id == get_field(changeset, :id) do
        add_error(changeset, :parent_role_id, "cannot be self-referential")
      else
        changeset
      end
    else
      changeset
    end
  end

  defp validate_max_users(changeset) do
    validate_number(changeset, :max_users, greater_than: 0)
  end

  defp set_system_role_defaults(changeset) do
    slug = get_field(changeset, :slug)

    if slug && Map.has_key?(@system_roles, slug) do
      config = Map.get(@system_roles, slug)

      changeset
      |> put_change(:hierarchy_level, config.level)
      |> put_change(:is_system, config[:system] || false)
    else
      changeset
    end
  end
end
