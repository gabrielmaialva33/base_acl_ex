defmodule BaseAclEx.Infrastructure.Security.Entities.AccessToken do
  @moduledoc """
  Access token entity for managing JWT token lifecycle.
  Tracks access and refresh tokens with revocation and metadata support.
  """

  use BaseAclEx.SharedKernel.Entity

  alias BaseAclEx.Accounts.Core.Entities.User

  @derive {Jason.Encoder, except: [:__meta__, :user, :refresh_token_parent]}

  schema "access_tokens" do
    field :token_hash, :string
    field :jti, :string
    field :token_type, :string
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime
    field :revoke_reason, :string
    field :last_used_at, :utc_datetime
    field :used_count, :integer, default: 0
    field :ip_address, :string  # Using string for IP storage (compatible with INET)
    field :user_agent, :string
    field :device_id, :string
    field :device_name, :string
    field :scopes, {:array, :string}, default: []
    field :metadata, :map, default: %{}

    belongs_to :user, User
    belongs_to :revoked_by, User, foreign_key: :revoked_by_id
    belongs_to :refresh_token_parent, __MODULE__, foreign_key: :refresh_token_id

    timestamps(type: :utc_datetime)
  end

  @type token_type :: :access | :refresh | :api | :personal | :service

  @required_fields [:user_id, :token_hash, :jti, :token_type, :expires_at]
  @optional_fields [
    :revoked_at,
    :revoked_by_id,
    :revoke_reason,
    :last_used_at,
    :used_count,
    :ip_address,
    :user_agent,
    :device_id,
    :device_name,
    :scopes,
    :metadata,
    :refresh_token_id
  ]

  @doc """
  Creates a new access token record.
  """
  def new(attrs) do
    %__MODULE__{}
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_token_type()
    |> validate_expiration()
    |> unique_constraint(:token_hash)
    |> unique_constraint(:jti)
  end

  @doc """
  Creates a changeset for updating token usage.
  """
  def update_usage(%__MODULE__{} = token, ip_address \\ nil) do
    attrs = %{
      last_used_at: DateTime.utc_now(),
      used_count: token.used_count + 1
    }

    attrs = if ip_address, do: Map.put(attrs, :ip_address, ip_address), else: attrs

    change(token, attrs)
  end

  @doc """
  Creates a changeset for revoking a token.
  """
  def revoke(%__MODULE__{} = token, revoked_by_id \\ nil, reason \\ nil) do
    change(token, %{
      revoked_at: DateTime.utc_now(),
      revoked_by_id: revoked_by_id,
      revoke_reason: reason
    })
  end

  @doc """
  Checks if token is expired.
  """
  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(expires_at, DateTime.utc_now()) == :lt
  end

  @doc """
  Checks if token is revoked.
  """
  def revoked?(%__MODULE__{revoked_at: nil}), do: false
  def revoked?(%__MODULE__{}), do: true

  @doc """
  Checks if token is active (not expired and not revoked).
  """
  def active?(%__MODULE__{} = token) do
    !expired?(token) && !revoked?(token)
  end

  @doc """
  Gets token type as atom.
  """
  def token_type_atom(%__MODULE__{token_type: "access"}), do: :access
  def token_type_atom(%__MODULE__{token_type: "refresh"}), do: :refresh
  def token_type_atom(%__MODULE__{token_type: "api"}), do: :api
  def token_type_atom(%__MODULE__{token_type: "personal"}), do: :personal
  def token_type_atom(%__MODULE__{token_type: "service"}), do: :service

  @doc """
  Checks if token should be rotated based on age or usage.
  """
  def should_rotate?(%__MODULE__{token_type: "refresh"} = token) do
    # Rotate refresh tokens after 50% of their lifetime or after 10 uses
    lifetime_50_percent =
      DateTime.diff(token.expires_at, token.inserted_at, :second) / 2

    age_threshold = DateTime.add(token.inserted_at, trunc(lifetime_50_percent), :second)

    DateTime.compare(DateTime.utc_now(), age_threshold) == :gt || token.used_count >= 10
  end

  def should_rotate?(_), do: false

  # Private functions

  defp validate_token_type(changeset) do
    changeset
    |> validate_inclusion(:token_type, ~w(access refresh api personal service))
  end

  defp validate_expiration(changeset) do
    case get_field(changeset, :expires_at) do
      nil ->
        changeset

      expires_at ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
          changeset
        else
          add_error(changeset, :expires_at, "must be in the future")
        end
    end
  end
end
