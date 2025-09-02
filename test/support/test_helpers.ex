defmodule BaseAclEx.TestSupport.TestHelpers do
  @moduledoc """
  Common test helpers and assertion utilities.
  """

  import ExUnit.Assertions
  import Ecto.Query
  alias BaseAclEx.Repo

  @doc """
  Asserts that a changeset has specific errors.
  """
  def assert_changeset_error(changeset, field, message) when is_binary(message) do
    assert changeset.errors[field], "Expected error on field #{field}"

    assert message in errors_on_field(changeset, field),
           "Expected #{inspect(message)} in #{inspect(errors_on_field(changeset, field))}"
  end

  def assert_changeset_error(changeset, field, message_regex) do
    assert changeset.errors[field], "Expected error on field #{field}"
    errors = errors_on_field(changeset, field)

    assert Enum.any?(errors, &String.match?(&1, message_regex)),
           "Expected error matching #{inspect(message_regex)} in #{inspect(errors)}"
  end

  @doc """
  Asserts that a changeset does not have errors on specific field.
  """
  def refute_changeset_error(changeset, field) do
    refute changeset.errors[field], "Expected no error on field #{field}"
  end

  @doc """
  Asserts that a changeset is valid.
  """
  def assert_changeset_valid(changeset) do
    assert changeset.valid?,
           "Expected changeset to be valid, got errors: #{inspect(changeset.errors)}"
  end

  @doc """
  Asserts that a changeset is invalid.
  """
  def assert_changeset_invalid(changeset) do
    refute changeset.valid?, "Expected changeset to be invalid"
  end

  @doc """
  Asserts that a record exists in the database.
  """
  def assert_record_exists(queryable, conditions) do
    query = from(q in queryable, where: ^conditions)
    assert Repo.exists?(query), "Expected record to exist with conditions #{inspect(conditions)}"
  end

  @doc """
  Asserts that a record does not exist in the database.
  """
  def refute_record_exists(queryable, conditions) do
    query = from(q in queryable, where: ^conditions)

    refute Repo.exists?(query),
           "Expected no record to exist with conditions #{inspect(conditions)}"
  end

  @doc """
  Asserts that the count of records matches expectation.
  """
  def assert_record_count(queryable, expected_count, conditions \\ []) do
    query =
      if conditions == [] do
        queryable
      else
        from(q in queryable, where: ^conditions)
      end

    actual_count = Repo.aggregate(query, :count, :id)

    assert actual_count == expected_count,
           "Expected #{expected_count} records, got #{actual_count}"
  end

  @doc """
  Asserts that a domain event is present.
  """
  def assert_domain_event(events, event_type) when is_list(events) do
    assert Enum.any?(events, &(&1.type == event_type)),
           "Expected domain event #{event_type} in #{inspect(Enum.map(events, & &1.type))}"
  end

  def assert_domain_event(%{domain_events: events}, event_type) do
    assert_domain_event(events, event_type)
  end

  @doc """
  Asserts that a domain event is not present.
  """
  def refute_domain_event(events, event_type) when is_list(events) do
    refute Enum.any?(events, &(&1.type == event_type)),
           "Expected no domain event #{event_type} in #{inspect(Enum.map(events, & &1.type))}"
  end

  def refute_domain_event(%{domain_events: events}, event_type) do
    refute_domain_event(events, event_type)
  end

  @doc """
  Asserts that domain event has specific payload data.
  """
  def assert_domain_event_payload(events, event_type, payload_assertions) when is_list(events) do
    event = Enum.find(events, &(&1.type == event_type))
    assert event, "Expected domain event #{event_type}"

    Enum.each(payload_assertions, fn {key, expected_value} ->
      actual_value = get_in(event.payload, [key])

      assert actual_value == expected_value,
             "Expected event payload #{key} to be #{inspect(expected_value)}, got #{inspect(actual_value)}"
    end)
  end

  @doc """
  Asserts that a value is a valid UUID.
  """
  def assert_uuid(value) do
    assert is_binary(value)

    assert String.match?(
             value,
             ~r/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
           ),
           "Expected valid UUID, got: #{value}"
  end

  @doc """
  Asserts that a DateTime is recent (within last minute).
  """
  def assert_recent_datetime(datetime) do
    now = DateTime.utc_now()
    diff = DateTime.diff(now, datetime, :second)

    assert diff >= 0 and diff <= 60,
           "Expected datetime to be within last 60 seconds, got #{diff} seconds ago"
  end

  @doc """
  Asserts that a value is within a time range.
  """
  def assert_datetime_within(datetime, reference_time, seconds \\ 5) do
    diff = abs(DateTime.diff(datetime, reference_time, :second))

    assert diff <= seconds,
           "Expected datetime to be within #{seconds} seconds of reference, got #{diff} seconds"
  end

  @doc """
  Asserts that an email address is valid format.
  """
  def assert_valid_email(email) do
    assert String.match?(email, ~r/^[^\s]+@[^\s]+$/),
           "Expected valid email format, got: #{email}"
  end

  @doc """
  Asserts that a password meets complexity requirements.
  """
  def assert_password_complexity(password) do
    assert String.length(password) >= 8, "Password must be at least 8 characters"
    assert String.match?(password, ~r/[a-z]/), "Password must contain lowercase letter"
    assert String.match?(password, ~r/[A-Z]/), "Password must contain uppercase letter"
    assert String.match?(password, ~r/[0-9]/), "Password must contain number"
    assert String.match?(password, ~r/[^A-Za-z0-9]/), "Password must contain special character"
  end

  @doc """
  Asserts that two maps are structurally equal (ignoring certain fields).
  """
  def assert_maps_equal(map1, map2, ignore_fields \\ []) do
    cleaned_map1 = Map.drop(map1, ignore_fields)
    cleaned_map2 = Map.drop(map2, ignore_fields)
    assert cleaned_map1 == cleaned_map2
  end

  @doc """
  Waits for a condition to be true within a timeout.
  """
  def wait_until(fun, timeout \\ 1000) do
    wait_until(fun, timeout, 10)
  end

  defp wait_until(fun, timeout, interval) when timeout > 0 do
    if fun.() do
      :ok
    else
      Process.sleep(interval)
      wait_until(fun, timeout - interval, interval)
    end
  end

  defp wait_until(_fun, _timeout, _interval) do
    flunk("Condition not met within timeout")
  end

  @doc """
  Flushes all messages from the current process mailbox.
  """
  def flush_messages do
    receive do
      _ -> flush_messages()
    after
      0 -> :ok
    end
  end

  @doc """
  Creates a mock context for permission testing.
  """
  def mock_permission_context(user, resource_id \\ nil) do
    %{
      current_user: user,
      resource_id: resource_id,
      ip_address: {127, 0, 0, 1},
      user_agent: "TestAgent/1.0",
      timestamp: DateTime.utc_now()
    }
  end

  # Private helpers

  defp errors_on_field(changeset, field) do
    changeset.errors
    |> Keyword.get_values(field)
    |> Enum.map(fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
