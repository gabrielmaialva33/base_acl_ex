defmodule BaseAclEx.Accounts.Core.Entities.User do
  @moduledoc """
  User entity representing a system user with authentication
  and profile information.
  """

  use BaseAclEx.SharedKernel.Entity
  import Ecto.Changeset
  
  alias BaseAclEx.Accounts.Core.ValueObjects.{Email, Password}
  alias BaseAclEx.SharedKernel.DomainEvent

  @derive {Jason.Encoder, except: [:__meta__, :password]}

  schema "users" do
    # Authentication
    field :email, :string
    field :username, :string
    field :password_hash, :string

    # Profile
    field :first_name, :string
    field :last_name, :string
    field :phone_number, :string
    field :avatar_url, :string

    # Status
    field :deleted_at, :utc_datetime
    field :locked_at, :utc_datetime

    # Verification
    field :email_verified_at, :utc_datetime

    # Security
    field :last_login_at, :utc_datetime
    field :last_login_ip, :string
    field :failed_attempts, :integer, default: 0
    field :login_count, :integer, default: 0
    field :two_factor_enabled, :boolean, default: false
    field :two_factor_secret, :string

    # Preferences
    field :newsletter_opt_in, :boolean, default: false
    field :terms_accepted_at, :utc_datetime

    # Metadata
    field :metadata, :map, default: %{}
    field :preferences, :map, default: %{}

    # Virtual fields
    field :password, :string, virtual: true
    field :password_confirmation, :string, virtual: true
    field :current_password, :string, virtual: true
    field :domain_events, {:array, :any}, virtual: true, default: []

    timestamps(type: :utc_datetime)
  end

  @required_fields [:email, :password]
  @optional_fields [
    :username,
    :first_name,
    :last_name,
    :phone_number,
    :avatar_url,
    :metadata,
    :preferences,
    :two_factor_enabled
  ]
  @update_fields [
    :first_name,
    :last_name,
    :phone_number,
    :avatar_url,
    :username,
    :metadata,
    :preferences
  ]

  @doc """
  Creates a new user with the given attributes.
  """
  def new(attrs) do
    %__MODULE__{}
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_email()
    |> validate_password()
    |> validate_username()
    |> hash_password()
    |> add_creation_event()
  end

  @doc """
  Updates user profile information.
  """
  def update_profile(%__MODULE__{} = user, attrs) do
    user
    |> cast(attrs, @update_fields)
    |> validate_username()
    |> validate_phone()
    |> add_update_event()
  end

  @doc """
  Changes user password.
  """
  def change_password(%__MODULE__{} = user, attrs) do
    user
    |> cast(attrs, [:current_password, :password, :password_confirmation])
    |> validate_current_password(user)
    |> validate_password()
    |> validate_confirmation(:password)
    |> hash_password()
    |> add_password_changed_event()
  end

  @doc """
  Marks email as verified.
  """
  def verify_email(%__MODULE__{} = user) do
    user
    |> change(%{email_verified_at: DateTime.utc_now()})
    |> add_email_verified_event()
  end

  @doc """
  Records a successful login.
  """
  def record_login(%__MODULE__{} = user, ip_address \\ nil) do
    user
    |> change(%{
      last_login_at: DateTime.utc_now(),
      failed_attempts: 0,
      locked_at: nil
    })
    |> add_login_event(ip_address)
  end

  @doc """
  Records a failed login attempt.
  """
  def record_failed_login(%__MODULE__{} = user) do
    attempts = user.failed_attempts + 1
    locked_at = if attempts >= 5, do: DateTime.add(DateTime.utc_now(), 900, :second), else: nil

    user
    |> change(%{
      failed_attempts: attempts,
      locked_at: locked_at
    })
    |> add_failed_login_event()
  end

  @doc """
  Soft deletes the user.
  """
  def delete(%__MODULE__{} = user) do
    user
    |> change(%{
      deleted_at: DateTime.utc_now()
    })
    |> add_deletion_event()
  end

  @doc """
  Restores a soft-deleted user.
  """
  def restore(%__MODULE__{} = user) do
    user
    |> change(%{
      deleted_at: nil
    })
    |> add_restoration_event()
  end

  @doc """
  Enables two-factor authentication.
  """
  def enable_two_factor(%__MODULE__{} = user, secret) do
    user
    |> change(%{
      two_factor_enabled: true,
      two_factor_secret: secret
    })
    |> add_two_factor_enabled_event()
  end

  @doc """
  Disables two-factor authentication.
  """
  def disable_two_factor(%__MODULE__{} = user) do
    user
    |> change(%{
      two_factor_enabled: false,
      two_factor_secret: nil
    })
    |> add_two_factor_disabled_event()
  end

  @doc """
  Checks if the user account is locked.
  """
  def locked?(%__MODULE__{locked_at: nil}), do: false

  def locked?(%__MODULE__{locked_at: locked_at}) do
    # Consider locked if it was locked in the last 15 minutes
    DateTime.compare(DateTime.utc_now(), DateTime.add(locked_at, 900, :second)) == :lt
  end

  @doc """
  Checks if the user can login.
  """
  def can_login?(%__MODULE__{} = user) do
    is_nil(user.deleted_at) && !locked?(user)
  end

  @doc """
  Checks if email is verified.
  """
  def email_verified?(%__MODULE__{email_verified_at: nil}), do: false
  def email_verified?(%__MODULE__{}), do: true

  @doc """
  Creates a changeset for user registration.
  """
  def registration_changeset(%__MODULE__{} = user, attrs) do
    user
    |> cast(attrs, [
      :email,
      :password_hash,
      :first_name,
      :last_name,
      :username,
      :phone_number,
      :newsletter_opt_in,
      :terms_accepted_at
    ])
    |> validate_required([:email, :password_hash, :first_name, :last_name])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> unique_constraint(:email)
    |> unique_constraint(:username)
  end

  @doc """
  Creates a changeset for updating user profile.
  """
  def update_changeset(%__MODULE__{} = user, attrs) do
    user
    |> cast(attrs, [:first_name, :last_name, :username, :phone_number, :avatar_url])
    |> validate_length(:first_name, min: 1, max: 100)
    |> validate_length(:last_name, min: 1, max: 100)
    |> validate_length(:username, min: 3, max: 50)
    |> unique_constraint(:username)
  end

  @doc """
  Creates a changeset for soft deleting a user.
  """
  def delete_changeset(%__MODULE__{} = user) do
    user
    |> change(%{deleted_at: DateTime.utc_now()})
  end

  @doc """
  Gets the user's full name.
  """
  def full_name(%__MODULE__{first_name: first, last_name: last}) do
    [first, last]
    |> Enum.filter(&(&1 && &1 != ""))
    |> Enum.join(" ")
  end

  @doc """
  Gets the user's display name (username or email).
  """
  def display_name(%__MODULE__{username: username}) when is_binary(username) and username != "",
    do: username

  def display_name(%__MODULE__{email: email}), do: email

  # Private functions

  defp validate_email(changeset) do
    changeset
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> validate_length(:email, max: 254)
    |> unique_constraint(:email, name: :users_email_unique_active)
    |> downcase_email()
  end

  defp validate_password(changeset) do
    changeset
    |> validate_required([:password])
    |> validate_length(:password, min: 8, max: 128)
    |> validate_format(:password, ~r/[a-z]/,
      message: "must contain at least one lowercase letter"
    )
    |> validate_format(:password, ~r/[A-Z]/,
      message: "must contain at least one uppercase letter"
    )
    |> validate_format(:password, ~r/[0-9]/, message: "must contain at least one number")
    |> validate_format(:password, ~r/[^A-Za-z0-9]/,
      message: "must contain at least one special character"
    )
  end

  defp validate_username(changeset) do
    changeset
    |> validate_length(:username, min: 3, max: 30)
    |> validate_format(:username, ~r/^[a-zA-Z0-9_-]+$/,
      message: "only letters, numbers, underscore and hyphen allowed"
    )
    |> unique_constraint(:username, name: :users_username_unique_active)
  end

  defp validate_phone(changeset) do
    changeset
    |> validate_format(:phone_number, ~r/^\+?[1-9]\d{1,14}$/,
      message: "must be a valid international phone number"
    )
  end

  defp validate_current_password(changeset, user) do
    case get_change(changeset, :current_password) do
      nil ->
        add_error(changeset, :current_password, "can't be blank")

      current_password ->
        if Argon2.verify_pass(current_password, user.password_hash) do
          changeset
        else
          add_error(changeset, :current_password, "is incorrect")
        end
    end
  end

  defp hash_password(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password ->
        changeset
        |> put_change(:password_hash, Argon2.hash_pwd_salt(password))
        |> delete_change(:password)
        |> delete_change(:password_confirmation)
    end
  end

  defp downcase_email(changeset) do
    case get_change(changeset, :email) do
      nil -> changeset
      email -> put_change(changeset, :email, String.downcase(email))
    end
  end

  # Domain Events

  defp add_creation_event(changeset) do
    add_domain_event(changeset, "user_created", %{
      email: get_field(changeset, :email),
      username: get_field(changeset, :username)
    })
  end

  defp add_update_event(changeset) do
    add_domain_event(changeset, "user_updated", %{
      changes: changeset.changes
    })
  end

  defp add_password_changed_event(changeset) do
    add_domain_event(changeset, "password_changed", %{})
  end

  defp add_email_verified_event(changeset) do
    add_domain_event(changeset, "email_verified", %{
      email: get_field(changeset, :email)
    })
  end

  defp add_login_event(changeset, ip_address) do
    add_domain_event(changeset, "user_logged_in", %{
      ip_address: ip_address,
      timestamp: DateTime.utc_now()
    })
  end

  defp add_failed_login_event(changeset) do
    add_domain_event(changeset, "login_failed", %{
      attempts: get_field(changeset, :failed_attempts)
    })
  end

  defp add_deletion_event(changeset) do
    add_domain_event(changeset, "user_deleted", %{})
  end

  defp add_restoration_event(changeset) do
    add_domain_event(changeset, "user_restored", %{})
  end

  defp add_two_factor_enabled_event(changeset) do
    add_domain_event(changeset, "two_factor_enabled", %{})
  end

  defp add_two_factor_disabled_event(changeset) do
    add_domain_event(changeset, "two_factor_disabled", %{})
  end

  defp add_domain_event(changeset, event_type, payload) do
    if changeset.valid? do
      event = %{
        type: event_type,
        aggregate_id: get_field(changeset, :id) || Ecto.UUID.generate(),
        payload: payload,
        occurred_at: DateTime.utc_now()
      }

      current_events = get_field(changeset, :domain_events) || []
      put_change(changeset, :domain_events, current_events ++ [event])
    else
      changeset
    end
  end
end
