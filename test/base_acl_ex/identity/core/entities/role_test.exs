defmodule BaseAclEx.Identity.Core.Entities.RoleTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Factory
  alias BaseAclEx.Identity.Core.Entities.Role
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  describe "new/1" do
    test "creates a valid role with required fields" do
      attrs = %{
        name: "Test Role",
        slug: "test_role",
        hierarchy_level: 50
      }

      changeset = Role.new(attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.name == "Test Role"
      assert changeset.changes.slug == "test_role"
      assert changeset.changes.hierarchy_level == 50
    end

    test "validates required fields" do
      changeset = Role.new(%{})

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :name, "can't be blank")
      assert_changeset_error(changeset, :slug, "can't be blank")
      assert_changeset_error(changeset, :hierarchy_level, "can't be blank")
    end

    test "generates slug from name when not provided" do
      attrs = %{
        name: "Test Role Name",
        hierarchy_level: 50
      }

      changeset = Role.new(attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.slug == "test_role_name"
    end

    test "validates slug format" do
      attrs = %{
        name: "Test Role",
        slug: "Invalid-Slug!",
        hierarchy_level: 50
      }

      changeset = Role.new(attrs)

      assert_changeset_invalid(changeset)

      assert_changeset_error(
        changeset,
        :slug,
        "must start with letter and contain only lowercase letters, numbers and underscores"
      )
    end

    test "validates name format and length" do
      # Test name too short
      changeset = Role.new(%{name: "A", slug: "a", hierarchy_level: 50})
      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :name, "should be at least 2 character(s)")

      # Test name too long
      long_name = String.duplicate("A", 101)
      changeset = Role.new(%{name: long_name, slug: "long", hierarchy_level: 50})
      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :name, "should be at most 100 character(s)")

      # Test name starting with non-letter
      changeset = Role.new(%{name: "123Role", slug: "role", hierarchy_level: 50})
      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :name, "must start with a letter")
    end

    test "validates hierarchy level range" do
      # Test negative level
      changeset = Role.new(%{name: "Test", slug: "test", hierarchy_level: -1})
      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :hierarchy_level, "must be greater than or equal to 0")

      # Test level too high
      changeset = Role.new(%{name: "Test", slug: "test", hierarchy_level: 1001})
      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :hierarchy_level, "must be less than or equal to 1000")
    end

    test "prevents self-referential parent role" do
      role_id = Ecto.UUID.generate()

      attrs = %{
        name: "Test Role",
        slug: "test_role",
        hierarchy_level: 50,
        parent_role_id: role_id
      }

      changeset = Role.new(attrs)
      changeset = put_in(changeset.data.id, role_id)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :parent_role_id, "cannot be self-referential")
    end

    test "enforces unique constraints" do
      existing_role = Factory.insert_role(%{name: "Existing Role", slug: "existing"})

      # Test name uniqueness
      assert_raise Ecto.ConstraintError, fn ->
        Role.new(%{name: "Existing Role", slug: "different", hierarchy_level: 50})
        |> Repo.insert!()
      end

      # Test slug uniqueness
      assert_raise Ecto.ConstraintError, fn ->
        Role.new(%{name: "Different Name", slug: "existing", hierarchy_level: 50})
        |> Repo.insert!()
      end
    end
  end

  describe "create_system_role/1" do
    test "creates valid system roles" do
      system_roles = ["root", "admin", "manager", "editor", "user", "guest"]

      for slug <- system_roles do
        changeset = Role.create_system_role(slug)

        assert_changeset_valid(changeset)
        assert changeset.changes.slug == slug
        assert changeset.changes.is_system == true
        assert changeset.changes.is_active == true
        assert changeset.changes.hierarchy_level > 0
      end
    end

    test "returns error for unknown system role" do
      assert {:error, :unknown_system_role} = Role.create_system_role("unknown")
    end

    test "sets correct hierarchy levels for system roles" do
      expected_levels = %{
        "root" => 100,
        "admin" => 90,
        "manager" => 70,
        "editor" => 50,
        "user" => 30,
        "guest" => 10
      }

      for {slug, expected_level} <- expected_levels do
        changeset = Role.create_system_role(slug)
        assert changeset.changes.hierarchy_level == expected_level
      end
    end
  end

  describe "update/2" do
    test "updates allowed fields for non-system roles" do
      role = Factory.insert_role(%{is_system: false})

      attrs = %{
        name: "Updated Role",
        description: "Updated description",
        is_active: false,
        color: "#FF5733",
        icon: "updated_icon",
        max_users: 100,
        features: ["feature1", "feature2"],
        metadata: %{"updated" => true}
      }

      changeset = Role.update(role, attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.name == "Updated Role"
      assert changeset.changes.description == "Updated description"
      assert changeset.changes.is_active == false
      assert changeset.changes.color == "#FF5733"
      assert changeset.changes.icon == "updated_icon"
      assert changeset.changes.max_users == 100
      assert changeset.changes.features == ["feature1", "feature2"]
      assert changeset.changes.metadata == %{"updated" => true}
    end

    test "prevents updating system roles" do
      system_role = Factory.insert_role(%{is_system: true})

      changeset = Role.update(system_role, %{name: "Hacked System Role"})

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :base, "system roles cannot be modified")
    end

    test "does not allow updating core fields" do
      role = Factory.insert_role(%{is_system: false})

      changeset =
        Role.update(role, %{
          slug: "new_slug",
          hierarchy_level: 999,
          is_system: true,
          parent_role_id: Ecto.UUID.generate()
        })

      refute Map.has_key?(changeset.changes, :slug)
      refute Map.has_key?(changeset.changes, :hierarchy_level)
      refute Map.has_key?(changeset.changes, :is_system)
      refute Map.has_key?(changeset.changes, :parent_role_id)
    end

    test "validates max_users when provided" do
      role = Factory.insert_role()

      changeset = Role.update(role, %{max_users: -1})
      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :max_users, "must be greater than 0")

      changeset = Role.update(role, %{max_users: 50})
      assert_changeset_valid(changeset)
      assert changeset.changes.max_users == 50
    end
  end

  describe "hierarchy comparisons" do
    test "higher_than?/2 compares hierarchy levels correctly" do
      admin_role = Factory.build_role(%{hierarchy_level: 90})
      user_role = Factory.build_role(%{hierarchy_level: 30})

      assert Role.higher_than?(admin_role, user_role)
      refute Role.higher_than?(user_role, admin_role)
    end

    test "lower_than?/2 compares hierarchy levels correctly" do
      admin_role = Factory.build_role(%{hierarchy_level: 90})
      user_role = Factory.build_role(%{hierarchy_level: 30})

      assert Role.lower_than?(user_role, admin_role)
      refute Role.lower_than?(admin_role, user_role)
    end

    test "same_level?/2 identifies equal hierarchy levels" do
      role1 = Factory.build_role(%{hierarchy_level: 50})
      role2 = Factory.build_role(%{hierarchy_level: 50})
      different_role = Factory.build_role(%{hierarchy_level: 60})

      assert Role.same_level?(role1, role2)
      refute Role.same_level?(role1, different_role)
    end
  end

  describe "role properties" do
    test "system_role?/1 identifies system roles" do
      system_role = Factory.build_system_role()
      regular_role = Factory.build_role(%{is_system: false})

      assert Role.system_role?(system_role)
      refute Role.system_role?(regular_role)
    end

    test "active?/1 checks role activation status" do
      active_role = Factory.build_role(%{is_active: true})
      inactive_role = Factory.build_role(%{is_active: false})

      assert Role.active?(active_role)
      refute Role.active?(inactive_role)
    end

    test "at_user_limit?/2 checks user limit constraints" do
      unlimited_role = Factory.build_role(%{max_users: nil})
      limited_role = Factory.build_role(%{max_users: 5})

      # Unlimited roles never reach limit
      refute Role.at_user_limit?(unlimited_role, 1000)

      # Limited roles check current count
      refute Role.at_user_limit?(limited_role, 3)
      assert Role.at_user_limit?(limited_role, 5)
      assert Role.at_user_limit?(limited_role, 7)
    end

    test "assignable?/1 checks if role can be assigned" do
      active_unlimited = Factory.build_role(%{is_active: true, max_users: nil, user_count: 10})
      inactive_role = Factory.build_role(%{is_active: false, max_users: nil, user_count: 0})
      at_limit_role = Factory.build_role(%{is_active: true, max_users: 5, user_count: 5})
      below_limit_role = Factory.build_role(%{is_active: true, max_users: 10, user_count: 5})

      assert Role.assignable?(active_unlimited)
      refute Role.assignable?(inactive_role)
      refute Role.assignable?(at_limit_role)
      assert Role.assignable?(below_limit_role)
    end

    test "has_feature?/2 checks feature availability" do
      role_with_features = Factory.build_role(%{features: ["dashboard", "reports", "analytics"]})
      role_without_features = Factory.build_role(%{features: []})

      assert Role.has_feature?(role_with_features, "dashboard")
      assert Role.has_feature?(role_with_features, "reports")
      refute Role.has_feature?(role_with_features, "missing_feature")

      refute Role.has_feature?(role_without_features, "any_feature")
    end
  end

  describe "role activation" do
    test "activate/1 sets role as active" do
      role = Factory.build_role(%{is_active: false})
      changeset = Role.activate(role)

      assert changeset.changes.is_active == true
    end

    test "deactivate/1 sets role as inactive" do
      role = Factory.build_role(%{is_active: true})
      changeset = Role.deactivate(role)

      assert changeset.changes.is_active == false
    end
  end

  describe "parent role management" do
    test "set_parent/2 sets valid parent role" do
      parent_role = Factory.build_role(%{hierarchy_level: 80})
      child_role = Factory.build_role(%{hierarchy_level: 60})

      changeset = Role.set_parent(child_role, parent_role)

      assert_changeset_valid(changeset)
      assert changeset.changes.parent_role_id == parent_role.id
    end

    test "set_parent/2 prevents invalid hierarchy" do
      parent_role = Factory.build_role(%{hierarchy_level: 50})
      child_role = Factory.build_role(%{hierarchy_level: 80})

      changeset = Role.set_parent(child_role, parent_role)

      assert_changeset_invalid(changeset)

      assert_changeset_error(
        changeset,
        :parent_role_id,
        "parent role must have higher hierarchy level"
      )
    end

    test "set_parent/2 allows equal level assignment" do
      parent_role = Factory.build_role(%{hierarchy_level: 50})
      child_role = Factory.build_role(%{hierarchy_level: 50})

      changeset = Role.set_parent(child_role, parent_role)

      # Should not set parent since hierarchy levels are equal
      refute Map.has_key?(changeset.changes, :parent_role_id)
    end
  end

  describe "system role utilities" do
    test "system_role_slugs/0 returns all system role slugs" do
      slugs = Role.system_role_slugs()

      expected_slugs = ["root", "admin", "manager", "editor", "user", "guest"]
      assert Enum.sort(slugs) == Enum.sort(expected_slugs)
    end

    test "display_name/1 returns role name" do
      role = Factory.build_role(%{name: "Test Role"})
      assert Role.display_name(role) == "Test Role"
    end
  end

  describe "slug generation" do
    test "generates slug from name with special character handling" do
      test_cases = [
        {"Simple Role", "simple_role"},
        {"Role With Spaces", "role_with_spaces"},
        {"Role-With-Hyphens", "role_with_hyphens"},
        {"Role123 Numbers", "role123_numbers"},
        {"Role!@#$%Special", "role_special"},
        {"  Leading Trailing  ", "leading_trailing"}
      ]

      for {name, expected_slug} <- test_cases do
        changeset =
          Role.new(%{
            name: name,
            hierarchy_level: 50
          })

        assert changeset.changes.slug == expected_slug,
               "Name '#{name}' should generate slug '#{expected_slug}', got '#{changeset.changes.slug}'"
      end
    end

    test "preserves manually set slug" do
      attrs = %{
        name: "Test Role",
        slug: "custom_slug",
        hierarchy_level: 50
      }

      changeset = Role.new(attrs)

      assert changeset.changes.slug == "custom_slug"
    end
  end

  describe "system role configuration" do
    test "automatically sets system role properties" do
      # Test that creating a role with a system slug gets system properties
      changeset =
        Role.new(%{
          name: "Custom Admin Name",
          slug: "admin",
          # This should be overridden
          hierarchy_level: 999
        })

      # Admin level from system config
      assert changeset.changes.hierarchy_level == 90
      assert changeset.changes.is_system == true
    end

    test "does not modify non-system roles" do
      changeset =
        Role.new(%{
          name: "Regular Role",
          slug: "regular_role",
          hierarchy_level: 45,
          is_system: false
        })

      assert changeset.changes.hierarchy_level == 45
      refute Map.has_key?(changeset.changes, :is_system) || changeset.changes.is_system == false
    end
  end
end
