defmodule BaseAclExWeb.Helpers do
  def keys_to_atoms(json) when is_map(json) do
    Map.new(json, &reduce_keys_to_atoms/1)
  end

  def reduce_keys_to_atoms({key, val}) when is_map(val),
    do: {String.to_existing_atom(key), keys_to_atoms(val)}

  def reduce_keys_to_atoms({key, val}) when is_list(val),
    do: {String.to_existing_atom(key), Enum.map(val, &keys_to_atoms(&1))}

  def reduce_keys_to_atoms({key, val}), do: {String.to_existing_atom(key), val}
end
