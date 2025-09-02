defmodule BaseAclEx.Identity.Application.Services.PermissionCache do
  @moduledoc """
  High-performance permission caching service using ETS and Cachex.
  Provides sub-millisecond permission checks.
  """

  use GenServer
  require Logger
  import Cachex.Spec

  @cache_name :permission_cache
  @ets_table :permission_ets
  @user_permission_ttl :timer.hours(1)
  @role_permission_ttl :timer.hours(2)
  @permission_list_ttl :timer.hours(6)

  # Client API

  @doc """
  Starts the permission cache service.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Checks if a user has a specific permission (fastest check).
  """
  def has_permission?(user_id, permission_name, scope \\ "any") do
    cache_key = permission_key(user_id, permission_name, scope)

    # First check ETS for ultra-fast lookup
    case :ets.lookup(@ets_table, cache_key) do
      [{^cache_key, result, expires_at}] ->
        if DateTime.compare(DateTime.utc_now(), expires_at) == :lt do
          {:ok, result}
        else
          # Expired, check Cachex
          check_cachex_and_ets(cache_key, user_id, permission_name, scope)
        end

      [] ->
        # Not in ETS, check Cachex
        check_cachex_and_ets(cache_key, user_id, permission_name, scope)
    end
  end

  @doc """
  Gets all permissions for a user.
  """
  def get_user_permissions(user_id) do
    cache_key = user_permissions_key(user_id)

    case Cachex.get(@cache_name, cache_key) do
      {:ok, nil} ->
        {:miss, nil}

      {:ok, permissions} ->
        {:ok, permissions}

      {:error, reason} ->
        Logger.error("Failed to get user permissions from cache: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Sets user permissions in cache.
  """
  def set_user_permissions(user_id, permissions) do
    cache_key = user_permissions_key(user_id)

    # Store in Cachex
    case Cachex.put(@cache_name, cache_key, permissions, ttl: @user_permission_ttl) do
      {:ok, _} ->
        # Also update ETS for specific permission checks
        update_ets_permissions(user_id, permissions)
        {:ok, permissions}

      {:error, reason} ->
        Logger.error("Failed to cache user permissions: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Gets role permissions from cache.
  """
  def get_role_permissions(role_id) do
    cache_key = role_permissions_key(role_id)

    case Cachex.get(@cache_name, cache_key) do
      {:ok, nil} ->
        {:miss, nil}

      {:ok, permissions} ->
        {:ok, permissions}

      {:error, reason} ->
        Logger.error("Failed to get role permissions from cache: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Sets role permissions in cache.
  """
  def set_role_permissions(role_id, permissions) do
    cache_key = role_permissions_key(role_id)

    case Cachex.put(@cache_name, cache_key, permissions, ttl: @role_permission_ttl) do
      {:ok, _} ->
        {:ok, permissions}

      {:error, reason} ->
        Logger.error("Failed to cache role permissions: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Invalidates all cache entries for a user.
  """
  def invalidate_user(user_id) do
    # Remove from Cachex
    cache_key = user_permissions_key(user_id)
    Cachex.del(@cache_name, cache_key)

    # Remove from ETS
    pattern = {{:user_permission, user_id, :_, :_}, :_, :_}
    :ets.match_delete(@ets_table, pattern)

    :ok
  end

  @doc """
  Invalidates all cache entries for a role.
  """
  def invalidate_role(role_id) do
    cache_key = role_permissions_key(role_id)
    Cachex.del(@cache_name, cache_key)

    # Also invalidate all users with this role
    # In production, this would be more sophisticated
    broadcast_role_invalidation(role_id)

    :ok
  end

  @doc """
  Warms the cache for a user.
  """
  def warm_user_cache(user_id, permissions) do
    set_user_permissions(user_id, permissions)
  end

  @doc """
  Gets cache statistics.
  """
  def stats do
    cachex_stats = Cachex.stats(@cache_name)
    ets_info = :ets.info(@ets_table)

    %{
      cachex: cachex_stats,
      ets: %{
        size: Keyword.get(ets_info, :size, 0),
        memory: Keyword.get(ets_info, :memory, 0)
      }
    }
  end

  @doc """
  Clears all cache entries.
  """
  def clear_all do
    Cachex.clear(@cache_name)
    :ets.delete_all_objects(@ets_table)
    :ok
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for ultra-fast lookups
    :ets.new(@ets_table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Start Cachex if not already started
    case Cachex.start_link(@cache_name,
           stats: true,
           transactions: true,
           expiration:
             expiration(
               default: @user_permission_ttl,
               interval: :timer.minutes(5),
               lazy: true
             )
         ) do
      {:ok, _} ->
        Logger.info("Permission cache started successfully")

      {:error, {:already_started, _}} ->
        Logger.info("Permission cache already running")

      error ->
        Logger.error("Failed to start permission cache: #{inspect(error)}")
    end

    # Schedule periodic cleanup
    schedule_cleanup()

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_expired_ets_entries()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info({:invalidate_role, role_id}, state) do
    # Handle role invalidation broadcasts
    invalidate_users_with_role(role_id)
    {:noreply, state}
  end

  # Private functions

  defp check_cachex_and_ets(cache_key, user_id, permission_name, scope) do
    user_cache_key = user_permissions_key(user_id)

    case Cachex.get(@cache_name, user_cache_key) do
      {:ok, nil} ->
        {:miss, nil}

      {:ok, permissions} ->
        result = check_permission_in_list(permissions, permission_name, scope)

        # Update ETS for next lookup
        expires_at = DateTime.add(DateTime.utc_now(), @user_permission_ttl, :millisecond)
        :ets.insert(@ets_table, {cache_key, result, expires_at})

        {:ok, result}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp check_permission_in_list(permissions, permission_name, scope) do
    Enum.any?(permissions, fn perm ->
      perm_name = Map.get(perm, :name) || Map.get(perm, "name")
      perm_scope = Map.get(perm, :scope) || Map.get(perm, "scope") || "any"

      perm_name == permission_name && scope_satisfies?(perm_scope, scope)
    end)
  end

  defp scope_satisfies?(user_scope, required_scope) do
    user_scope == required_scope ||
      user_scope == "global" ||
      (user_scope == "any" && required_scope != "global")
  end

  defp update_ets_permissions(user_id, permissions) do
    expires_at = DateTime.add(DateTime.utc_now(), @user_permission_ttl, :millisecond)

    # Pre-compute common permission checks and store in ETS
    Enum.each(permissions, fn perm ->
      name = Map.get(perm, :name) || Map.get(perm, "name")
      scope = Map.get(perm, :scope) || Map.get(perm, "scope") || "any"

      # Store multiple scope variations for fast lookup
      Enum.each(["any", "own", scope], fn check_scope ->
        key = permission_key(user_id, name, check_scope)
        result = scope_satisfies?(scope, check_scope)
        :ets.insert(@ets_table, {key, result, expires_at})
      end)
    end)
  end

  defp cleanup_expired_ets_entries do
    now = DateTime.utc_now()

    :ets.foldl(
      fn
        {key, _result, expires_at}, acc ->
          if DateTime.compare(now, expires_at) == :gt do
            :ets.delete(@ets_table, key)
          end

          acc
      end,
      nil,
      @ets_table
    )
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.minutes(10))
  end

  defp broadcast_role_invalidation(role_id) do
    # In production, use PubSub to broadcast to all nodes
    Phoenix.PubSub.broadcast(
      BaseAclEx.PubSub,
      "permission_cache",
      {:invalidate_role, role_id}
    )
  end

  defp invalidate_users_with_role(_role_id) do
    # In production, this would query users with the role
    # and invalidate their caches
    :ok
  end

  # Cache key generators

  defp permission_key(user_id, permission_name, scope) do
    {:user_permission, user_id, permission_name, scope}
  end

  defp user_permissions_key(user_id) do
    "user_permissions:#{user_id}"
  end

  defp role_permissions_key(role_id) do
    "role_permissions:#{role_id}"
  end
end
