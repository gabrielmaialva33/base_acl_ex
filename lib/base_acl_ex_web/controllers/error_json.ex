defmodule BaseAclExWeb.ErrorJSON do
  @moduledoc """
  This module is invoked by your endpoint in case of errors on JSON requests.

  See config/config.exs.
  """

  # Handle changeset errors
  def error(%{changeset: changeset}) do
    %{
      errors: translate_errors(changeset)
    }
  end

  # Handle simple message errors
  def error(%{message: message}) do
    %{
      error: %{
        message: message
      }
    }
  end

  # Handle validation errors list
  def validation_errors(%{errors: errors}) do
    %{
      errors: format_validation_errors(errors)
    }
  end

  # Default error handler
  def render(template, _assigns) do
    %{errors: %{detail: Phoenix.Controller.status_message_from_template(template)}}
  end

  # Private functions

  defp translate_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp format_validation_errors(errors) when is_list(errors) do
    Enum.map(errors, fn
      {field, message} -> %{field: field, message: message}
      error -> %{message: to_string(error)}
    end)
  end
end
