defmodule BaseAclEx.Identity.Core.ValueObjects.Resource do
  @moduledoc """
  Resource value object representing a system resource that can be protected.
  Examples: "users", "posts", "reports", "dashboard"
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  embedded_schema do
    field :name, :string
    field :category, :string
    field :description, :string
  end

  @valid_resources ~w(
    users roles permissions
    posts comments articles
    reports analytics dashboard
    settings system audit_logs
    files documents images
    api webhooks integrations
  )

  @doc """
  Creates a new Resource value object.
  """
  def new(name, category \\ nil) when is_binary(name) do
    normalized = normalize(name)

    if valid?(normalized) do
      {:ok,
       %__MODULE__{
         name: normalized,
         category: category || categorize(normalized)
       }}
    else
      {:error, :invalid_resource}
    end
  end

  def new(_, _), do: {:error, :invalid_resource}

  @doc """
  Validates if a resource name is valid.
  """
  def valid?(name) when is_binary(name) do
    normalized = normalize(name)
    normalized in @valid_resources || custom_resource_valid?(normalized)
  end

  def valid?(_), do: false

  @doc """
  Normalizes a resource name.
  """
  def normalize(name) when is_binary(name) do
    name
    |> String.trim()
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9_]/, "_")
  end

  def normalize(_), do: ""

  @doc """
  Categorizes a resource based on its name.
  """
  def categorize(name) when is_binary(name) do
    cond do
      name in ~w(users roles permissions) -> "identity"
      name in ~w(posts comments articles) -> "content"
      name in ~w(reports analytics dashboard) -> "analytics"
      name in ~w(settings system audit_logs) -> "system"
      name in ~w(files documents images) -> "storage"
      name in ~w(api webhooks integrations) -> "integration"
      true -> "custom"
    end
  end

  def categorize(_), do: "unknown"

  @doc """
  Returns all valid resources.
  """
  def all_resources, do: @valid_resources

  @doc """
  Returns resources by category.
  """
  def resources_by_category(category) do
    @valid_resources
    |> Enum.filter(&(categorize(&1) == category))
  end

  @doc """
  Checks if it's a system resource.
  """
  def system_resource?(name) do
    normalize(name) in ~w(system settings audit_logs roles permissions)
  end

  @doc """
  Returns the string representation.
  """
  def to_string(%__MODULE__{name: name}), do: name

  # Allow custom resources with specific pattern
  defp custom_resource_valid?(name) do
    String.match?(name, ~r/^[a-z][a-z0-9_]{2,49}$/)
  end

  defimpl String.Chars do
    alias BaseAclEx.Identity.Core.ValueObjects.Resource

    def to_string(resource), do: Resource.to_string(resource)
  end
end
