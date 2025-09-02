defmodule BaseAclEx.Identity.Application.Services.PermissionCacheTest do
  # async: false due to shared ETS table
  use BaseAclEx.DataCase, async: false

  alias BaseAclEx.Identity.Application.Services.PermissionCache
  alias BaseAclEx.Factory
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  @user_id Ecto.UUID.generate()
  @role_id Ecto.UUID.generate()

  setup do
    # Start the permission cache if not already running
    case GenServer.whereis(PermissionCache) do
      nil ->
        {:ok, _} = PermissionCache.start_link()

      _pid ->
        :ok
    end

    # Clear cache before each test
    PermissionCache.clear_all()

    on_exit(fn ->
      PermissionCache.clear_all()
    end)

    :ok
  end

  describe "has_permission?/3" do
    test "returns miss when user has no cached permissions" do
      assert {:miss, nil} = PermissionCache.has_permission?(@user_id, "posts.read", "any")
    end

    test "returns true when user has the requested permission" do
      permissions = [
        %{"name" => "posts.read.any", "scope" => "any"},
        %{"name" => "posts.create.any", "scope" => "any"},
        %{"name" => "comments.read.own", "scope" => "own"}
      ]

      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.create.any", "any")
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "comments.read.own", "own")
    end

    test "returns false when user does not have the requested permission" do
      permissions = [
        %{"name" => "posts.read.any", "scope" => "any"}
      ]

      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      assert {:ok, false} = PermissionCache.has_permission?(@user_id, "posts.delete.any", "any")
      assert {:ok, false} = PermissionCache.has_permission?(@user_id, "users.read.any", "any")
    end

    test "handles scope hierarchy correctly" do
      permissions = [
        %{"name" => "posts.read.any", "scope" => "global"},
        %{"name" => "comments.read.any", "scope" => "any"},
        %{"name" => "files.read.any", "scope" => "own"}
      ]

      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # Global scope should satisfy any scope requirement
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "global")
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "own")

      # "any" scope should satisfy "any" but not "global"
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "comments.read.any", "any")
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "comments.read.any", "own")

      assert {:ok, false} =
               PermissionCache.has_permission?(@user_id, "comments.read.any", "global")

      # "own" scope should only satisfy "own"
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "files.read.any", "own")
      assert {:ok, false} = PermissionCache.has_permission?(@user_id, "files.read.any", "any")
      assert {:ok, false} = PermissionCache.has_permission?(@user_id, "files.read.any", "global")
    end

    test "uses ETS for ultra-fast subsequent lookups" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # First lookup should populate ETS
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      # Verify ETS entry exists
      cache_key = {:user_permission, @user_id, "posts.read.any", "any"}
      assert :ets.lookup(:permission_ets, cache_key) != []

      # Second lookup should be faster (from ETS)
      {time, result} =
        :timer.tc(fn ->
          PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
        end)

      assert {:ok, true} = result
      # ETS lookup should be very fast (typically < 10 microseconds)
      assert time < 1000, "ETS lookup took #{time} microseconds, expected < 1000"
    end

    test "handles expired ETS entries correctly" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # Get the permission to populate ETS
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      # Manually expire the ETS entry by setting past expiration
      cache_key = {:user_permission, @user_id, "posts.read.any", "any"}
      past_time = DateTime.add(DateTime.utc_now(), -3600, :second)
      :ets.insert(:permission_ets, {cache_key, true, past_time})

      # Should fall back to Cachex and refresh ETS
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      # ETS should be refreshed with new expiration
      [{^cache_key, true, expires_at}] = :ets.lookup(:permission_ets, cache_key)
      assert DateTime.compare(expires_at, DateTime.utc_now()) == :gt
    end
  end

  describe "get_user_permissions/1" do
    test "returns miss when user has no cached permissions" do
      assert {:miss, nil} = PermissionCache.get_user_permissions(@user_id)
    end

    test "returns cached user permissions" do
      permissions = [
        %{"name" => "posts.read.any", "scope" => "any"},
        %{"name" => "posts.create.any", "scope" => "any"}
      ]

      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      assert {:ok, cached_permissions} = PermissionCache.get_user_permissions(@user_id)
      assert cached_permissions == permissions
    end
  end

  describe "set_user_permissions/2" do
    test "successfully caches user permissions" do
      permissions = [
        %{"name" => "posts.read.any", "scope" => "any"},
        %{"name" => "users.update.own", "scope" => "own"}
      ]

      assert {:ok, cached_permissions} =
               PermissionCache.set_user_permissions(@user_id, permissions)

      assert cached_permissions == permissions

      # Verify they're actually cached
      assert {:ok, ^permissions} = PermissionCache.get_user_permissions(@user_id)
    end

    test "updates ETS with precomputed permission checks" do
      permissions = [
        %{"name" => "posts.read.any", "scope" => "any"},
        %{"name" => "files.delete.any", "scope" => "global"}
      ]

      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # Verify ETS entries were created for different scope checks
      ets_entries = :ets.tab2list(:permission_ets)

      # Should have entries for precomputed permission checks
      assert length(ets_entries) > 0

      # Check specific entries exist
      any_key = {:user_permission, @user_id, "posts.read.any", "any"}
      own_key = {:user_permission, @user_id, "posts.read.any", "own"}

      assert :ets.lookup(:permission_ets, any_key) != []
      assert :ets.lookup(:permission_ets, own_key) != []
    end

    test "handles empty permissions list" do
      assert {:ok, []} = PermissionCache.set_user_permissions(@user_id, [])
      assert {:ok, []} = PermissionCache.get_user_permissions(@user_id)
    end

    test "handles large permissions list" do
      # Generate many permissions
      permissions =
        for i <- 1..100 do
          %{"name" => "resource#{i}.read.any", "scope" => "any"}
        end

      assert {:ok, cached} = PermissionCache.set_user_permissions(@user_id, permissions)
      assert length(cached) == 100

      # Verify some random permissions work
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "resource50.read.any", "any")

      assert {:ok, false} =
               PermissionCache.has_permission?(@user_id, "resource999.read.any", "any")
    end
  end

  describe "role permission caching" do
    test "caches and retrieves role permissions" do
      permissions = [
        %{"name" => "admin.read.any", "scope" => "global"},
        %{"name" => "admin.write.any", "scope" => "global"}
      ]

      assert {:ok, _} = PermissionCache.set_role_permissions(@role_id, permissions)
      assert {:ok, cached} = PermissionCache.get_role_permissions(@role_id)
      assert cached == permissions
    end

    test "returns miss for non-cached role" do
      assert {:miss, nil} = PermissionCache.get_role_permissions(@role_id)
    end
  end

  describe "invalidation" do
    test "invalidate_user/1 removes all user cache entries" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # Verify cached
      assert {:ok, _} = PermissionCache.get_user_permissions(@user_id)

      # Populate ETS
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
      ets_before = :ets.tab2list(:permission_ets)
      assert length(ets_before) > 0

      # Invalidate
      PermissionCache.invalidate_user(@user_id)

      # Verify Cachex cleared
      assert {:miss, nil} = PermissionCache.get_user_permissions(@user_id)

      # Verify ETS cleared for this user
      ets_after = :ets.tab2list(:permission_ets)
      assert length(ets_after) < length(ets_before)

      # Permission check should now miss
      assert {:miss, nil} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
    end

    test "invalidate_role/1 removes role cache" do
      permissions = [%{"name" => "admin.read.any", "scope" => "global"}]
      {:ok, _} = PermissionCache.set_role_permissions(@role_id, permissions)

      assert {:ok, _} = PermissionCache.get_role_permissions(@role_id)

      PermissionCache.invalidate_role(@role_id)

      assert {:miss, nil} = PermissionCache.get_role_permissions(@role_id)
    end
  end

  describe "cache warming" do
    test "warm_user_cache/2 preloads user permissions" do
      permissions = [
        %{"name" => "posts.read.any", "scope" => "any"},
        %{"name" => "comments.read.own", "scope" => "own"}
      ]

      assert {:ok, _} = PermissionCache.warm_user_cache(@user_id, permissions)

      # Should be immediately available
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
      assert {:ok, true} = PermissionCache.has_permission?(@user_id, "comments.read.own", "own")
      assert {:ok, false} = PermissionCache.has_permission?(@user_id, "admin.read.any", "global")
    end
  end

  describe "statistics and monitoring" do
    test "stats/0 returns cache statistics" do
      stats = PermissionCache.stats()

      assert stats.cachex
      assert stats.ets
      assert is_integer(stats.ets.size)
      assert is_integer(stats.ets.memory)
    end

    test "tracks cache usage" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      stats_before = PermissionCache.stats()
      initial_ets_size = stats_before.ets.size

      # Access cache multiple times
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      stats_after = PermissionCache.stats()

      # ETS size should have increased (due to precomputed entries)
      assert stats_after.ets.size >= initial_ets_size
    end
  end

  describe "clear_all/0" do
    test "clears both Cachex and ETS" do
      # Add some data
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)
      {:ok, _} = PermissionCache.set_role_permissions(@role_id, permissions)

      # Populate ETS
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      stats_before = PermissionCache.stats()
      assert stats_before.ets.size > 0

      # Clear all
      PermissionCache.clear_all()

      # Verify everything is cleared
      assert {:miss, nil} = PermissionCache.get_user_permissions(@user_id)
      assert {:miss, nil} = PermissionCache.get_role_permissions(@role_id)
      assert {:miss, nil} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      stats_after = PermissionCache.stats()
      assert stats_after.ets.size == 0
    end
  end

  describe "performance characteristics" do
    test "ETS lookups are faster than Cachex lookups" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # First lookup (Cachex + ETS population)
      {cachex_time, _} =
        :timer.tc(fn ->
          PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
        end)

      # Second lookup (ETS only)
      {ets_time, _} =
        :timer.tc(fn ->
          PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
        end)

      # ETS should be significantly faster
      assert ets_time < cachex_time
      # ETS lookup should be very fast (typically < 10 microseconds)
      assert ets_time < 1000
    end

    test "handles concurrent access correctly" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # Simulate concurrent access
      tasks =
        for _i <- 1..50 do
          Task.async(fn ->
            PermissionCache.has_permission?(@user_id, "posts.read.any", "any")
          end)
        end

      results = Task.await_many(tasks)

      # All should succeed
      assert Enum.all?(results, fn result -> result == {:ok, true} end)
    end

    test "handles cache misses efficiently" do
      # Test many cache misses
      user_ids = for _i <- 1..20, do: Ecto.UUID.generate()

      {time, results} =
        :timer.tc(fn ->
          Enum.map(user_ids, fn user_id ->
            PermissionCache.has_permission?(user_id, "posts.read.any", "any")
          end)
        end)

      # All should be misses
      assert Enum.all?(results, fn result -> result == {:miss, nil} end)

      # Should handle misses efficiently (< 100ms total for 20 misses)
      assert time < 100_000
    end
  end

  describe "edge cases and error handling" do
    test "handles malformed permission data gracefully" do
      malformed_permissions = [
        %{"invalid" => "structure"},
        %{"name" => nil, "scope" => "any"},
        # Missing scope
        %{"name" => "valid.permission.any"},
        nil
      ]

      # Should not crash, but behavior may vary
      case PermissionCache.set_user_permissions(@user_id, malformed_permissions) do
        {:ok, _} ->
          # If it succeeds, permission checks should handle malformed data
          {:miss, nil} = PermissionCache.has_permission?(@user_id, "valid.permission.any", "any")

        {:error, _} ->
          # Error is acceptable for malformed data
          :ok
      end
    end

    test "handles very long permission names" do
      long_permission_name = String.duplicate("long_permission_name_", 50) <> ".read.any"
      permissions = [%{"name" => long_permission_name, "scope" => "any"}]

      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)
      {:ok, true} = PermissionCache.has_permission?(@user_id, long_permission_name, "any")
    end

    test "handles non-string user IDs" do
      integer_user_id = 12345
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]

      {:ok, _} = PermissionCache.set_user_permissions(integer_user_id, permissions)
      {:ok, true} = PermissionCache.has_permission?(integer_user_id, "posts.read.any", "any")
    end

    test "permission names with special characters" do
      special_permissions = [
        %{"name" => "special-resource.read-write.any", "scope" => "any"},
        %{"name" => "resource_with_underscores.action.any", "scope" => "any"},
        %{"name" => "resource123.action456.any", "scope" => "any"}
      ]

      {:ok, _} = PermissionCache.set_user_permissions(@user_id, special_permissions)

      {:ok, true} =
        PermissionCache.has_permission?(@user_id, "special-resource.read-write.any", "any")

      {:ok, true} =
        PermissionCache.has_permission?(@user_id, "resource_with_underscores.action.any", "any")

      {:ok, true} = PermissionCache.has_permission?(@user_id, "resource123.action456.any", "any")
    end
  end

  describe "cache expiration and cleanup" do
    test "expired entries are cleaned up" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # Populate ETS
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      # Manually expire ETS entries
      cache_key = {:user_permission, @user_id, "posts.read.any", "any"}
      past_time = DateTime.add(DateTime.utc_now(), -3600, :second)
      :ets.insert(:permission_ets, {cache_key, true, past_time})

      # Trigger cleanup manually (normally done by periodic cleanup)
      GenServer.call(PermissionCache, :cleanup_expired_ets_entries)

      # Expired entry should be removed from ETS
      assert :ets.lookup(:permission_ets, cache_key) == []
    end

    test "unexpired entries are preserved during cleanup" do
      permissions = [%{"name" => "posts.read.any", "scope" => "any"}]
      {:ok, _} = PermissionCache.set_user_permissions(@user_id, permissions)

      # Populate ETS with fresh entry
      {:ok, true} = PermissionCache.has_permission?(@user_id, "posts.read.any", "any")

      cache_key = {:user_permission, @user_id, "posts.read.any", "any"}
      ets_before = :ets.lookup(:permission_ets, cache_key)
      assert length(ets_before) == 1

      # Trigger cleanup
      GenServer.call(PermissionCache, :cleanup_expired_ets_entries)

      # Fresh entry should still exist
      ets_after = :ets.lookup(:permission_ets, cache_key)
      assert length(ets_after) == 1
    end
  end
end
