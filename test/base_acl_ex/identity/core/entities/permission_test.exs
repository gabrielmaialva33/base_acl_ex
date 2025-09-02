defmodule BaseAclEx.Identity.Core.Entities.PermissionTest do
  use BaseAclEx.DataCase, async: true

  alias BaseAclEx.Factory
  alias BaseAclEx.Identity.Core.Entities.Permission

  import BaseAclEx.TestSupport.TestHelpers

  describe "new/1" do
    test "creates a valid permission with required fields" do
      attrs = %{
        resource: "posts",
        action: "read"
      }

      changeset = Permission.new(attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.resource == "posts"
      assert changeset.changes.action == "read"
      assert changeset.changes.context == "any"
      assert changeset.changes.name == "posts.read.any"
    end

    test "validates required fields" do
      changeset = Permission.new(%{})

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :resource, "can't be blank")
      assert_changeset_error(changeset, :action, "can't be blank")
    end

    test "validates resource format" do
      attrs = %{resource: "Invalid-Resource!", action: "read"}
      changeset = Permission.new(attrs)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :resource, "must be lowercase alphanumeric with underscores")
    end

    test "validates action format" do
      attrs = %{resource: "posts", action: "Invalid-Action!"}
      changeset = Permission.new(attrs)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :action, "must be lowercase alphanumeric with underscores or wildcard")
    end

    test "allows wildcard action" do
      attrs = %{resource: "posts", action: "*"}
      changeset = Permission.new(attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.action == "*"
    end

    test "validates context values" do
      attrs = %{resource: "posts", action: "read", context: "invalid_context"}
      changeset = Permission.new(attrs)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :context, "must be a valid context type")
    end

    test "accepts valid context values" do
      valid_contexts = ~w(any own team department organization project global)

      for context <- valid_contexts do
        attrs = %{resource: "posts", action: "read", context: context}
        changeset = Permission.new(attrs)

        assert_changeset_valid(changeset), "Context '#{context}' should be valid"
        assert changeset.changes.context == context
      end
    end

    test "validates risk level" do
      attrs = %{resource: "posts", action: "read", risk_level: "invalid"}
      changeset = Permission.new(attrs)

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :risk_level, "must be a valid risk level")
    end

    test "sets default values based on resource and action" do
      # Test high-risk action
      changeset = Permission.new(%{resource: "users", action: "delete"})
      assert changeset.changes.risk_level == "high"
      assert changeset.changes.category == "identity"

      # Test system resource
      changeset = Permission.new(%{resource: "permissions", action: "read"})
      assert changeset.changes.risk_level == "critical"
      assert changeset.changes.category == "identity"

      # Test low-risk action
      changeset = Permission.new(%{resource: "posts", action: "read"})
      assert changeset.changes.risk_level == "low"
      assert changeset.changes.category == "content"
    end

    test "sets ownership requirement for 'own' context" do
      changeset = Permission.new(%{resource: "posts", action: "read", context: "own"})
      assert changeset.changes.requires_ownership == true
    end

    test "generates unique name from components" do
      changeset = Permission.new(%{resource: "posts", action: "update", context: "own"})
      assert changeset.changes.name == "posts.update.own"
    end

    test "enforces uniqueness constraint" do
      existing_permission = Factory.insert_permission(%{
        resource: "posts", 
        action: "read", 
        context: "any"
      })

      assert_raise Ecto.ConstraintError, fn ->
        Permission.new(%{resource: "posts", action: "read", context: "any"})
        |> Repo.insert!()
      end
    end
  end

  describe "from_string/1" do
    test "parses permission string with three components" do
      result = Permission.from_string("posts.read.any")
      
      assert {:ok, changeset} = result
      assert changeset.changes.resource == "posts"
      assert changeset.changes.action == "read"
      assert changeset.changes.context == "any"
    end

    test "parses permission string with two components (defaults context)" do
      result = Permission.from_string("posts.read")
      
      assert {:ok, changeset} = result
      assert changeset.changes.resource == "posts"
      assert changeset.changes.action == "read"
      assert changeset.changes.context == "any"
    end

    test "returns error for invalid format" do
      assert {:error, :invalid_permission_format} = Permission.from_string("invalid")
      assert {:error, :invalid_permission_format} = Permission.from_string("too.many.parts.here")
    end
  end

  describe "from_components/3" do
    test "creates permission from separate components" do
      changeset = Permission.from_components("users", "create", "team")

      assert_changeset_valid(changeset)
      assert changeset.changes.resource == "users"
      assert changeset.changes.action == "create"
      assert changeset.changes.context == "team"
    end

    test "uses 'any' as default context" do
      changeset = Permission.from_components("users", "read")

      assert changeset.changes.context == "any"
    end
  end

  describe "update/2" do
    test "updates allowed fields" do
      permission = Factory.insert_permission()
      
      attrs = %{
        description: "Updated description",
        category: "updated_category",
        is_active: false,
        conditions: %{"time_based" => true},
        dependencies: ["other.permission"],
        metadata: %{"source" => "test"},
        requires_two_factor: true
      }

      changeset = Permission.update(permission, attrs)

      assert_changeset_valid(changeset)
      assert changeset.changes.description == "Updated description"
      assert changeset.changes.is_active == false
      assert changeset.changes.requires_two_factor == true
    end

    test "does not update core permission components" do
      permission = Factory.insert_permission()
      
      changeset = Permission.update(permission, %{
        resource: "new_resource",
        action: "new_action",
        context: "new_context"
      })

      refute Map.has_key?(changeset.changes, :resource)
      refute Map.has_key?(changeset.changes, :action)
      refute Map.has_key?(changeset.changes, :context)
    end

    test "validates conditions format" do
      permission = Factory.insert_permission()
      changeset = Permission.update(permission, %{conditions: "invalid"})

      assert_changeset_invalid(changeset)
      assert_changeset_error(changeset, :conditions, "must be a valid map")
    end
  end

  describe "wildcard?/1" do
    test "returns true for wildcard action" do
      permission = Factory.build_wildcard_permission()
      assert Permission.wildcard?(permission)
    end

    test "returns true for wildcard resource" do
      permission = Factory.build_permission(%{resource: "*", action: "read"})
      assert Permission.wildcard?(permission)
    end

    test "returns false for specific permissions" do
      permission = Factory.build_permission(%{resource: "posts", action: "read"})
      refute Permission.wildcard?(permission)
    end
  end

  describe "system_permission?/1" do
    test "returns true for system resources" do
      system_resources = ~w(permissions roles users system audit_logs)

      for resource <- system_resources do
        permission = Factory.build_permission(%{resource: resource})
        assert Permission.system_permission?(permission), "#{resource} should be system resource"
      end
    end

    test "returns false for non-system resources" do
      permission = Factory.build_permission(%{resource: "posts"})
      refute Permission.system_permission?(permission)
    end
  end

  describe "high_risk?/1" do
    test "returns true for high and critical risk levels" do
      high_risk = Factory.build_permission(%{risk_level: "high"})
      critical_risk = Factory.build_permission(%{risk_level: "critical"})

      assert Permission.high_risk?(high_risk)
      assert Permission.high_risk?(critical_risk)
    end

    test "returns false for low and medium risk levels" do
      low_risk = Factory.build_permission(%{risk_level: "low"})
      medium_risk = Factory.build_permission(%{risk_level: "medium"})

      refute Permission.high_risk?(low_risk)
      refute Permission.high_risk?(medium_risk)
    end
  end

  describe "requires_ownership?/1" do
    test "returns true for 'own' context" do
      permission = Factory.build_ownership_permission()
      assert Permission.requires_ownership?(permission)
    end

    test "returns true when requires_ownership flag is set" do
      permission = Factory.build_permission(%{
        context: "any",
        requires_ownership: true
      })
      assert Permission.requires_ownership?(permission)
    end

    test "returns false for other contexts without flag" do
      permission = Factory.build_permission(%{
        context: "any",
        requires_ownership: false
      })
      refute Permission.requires_ownership?(permission)
    end
  end

  describe "matches?/2" do
    test "matches exact permission" do
      permission = Factory.build_permission(%{
        resource: "posts",
        action: "read", 
        context: "any"
      })
      
      pattern = Factory.build_permission(%{
        resource: "posts",
        action: "read",
        context: "any"
      })

      assert Permission.matches?(permission, pattern)
    end

    test "matches wildcard resource" do
      permission = Factory.build_permission(%{resource: "posts", action: "read"})
      pattern = Factory.build_permission(%{resource: "*", action: "read"})

      assert Permission.matches?(permission, pattern)
    end

    test "matches wildcard action" do
      permission = Factory.build_permission(%{resource: "posts", action: "read"})
      pattern = Factory.build_permission(%{resource: "posts", action: "*"})

      assert Permission.matches?(permission, pattern)
    end

    test "matches wildcard context" do
      permission = Factory.build_permission(%{resource: "posts", action: "read", context: "own"})
      pattern = Factory.build_permission(%{resource: "posts", action: "read", context: "*"})

      assert Permission.matches?(permission, pattern)
    end

    test "does not match different resources" do
      permission = Factory.build_permission(%{resource: "posts", action: "read"})
      pattern = Factory.build_permission(%{resource: "users", action: "read"})

      refute Permission.matches?(permission, pattern)
    end
  end

  describe "full_name/1" do
    test "returns formatted permission name" do
      permission = Factory.build_permission(%{
        resource: "posts",
        action: "update",
        context: "own"
      })

      assert Permission.full_name(permission) == "posts.update.own"
    end
  end

  describe "display_name/1" do
    test "returns custom name when present" do
      permission = Factory.build_permission(%{
        name: "Custom Permission Name",
        resource: "posts",
        action: "read"
      })

      assert Permission.display_name(permission) == "Custom Permission Name"
    end

    test "falls back to full name when no custom name" do
      permission = Factory.build_permission(%{
        name: "",
        resource: "posts", 
        action: "read",
        context: "any"
      })

      assert Permission.display_name(permission) == "posts.read.any"
    end
  end

  describe "activate/1 and deactivate/1" do
    test "activate/1 sets is_active to true" do
      permission = Factory.build_permission(%{is_active: false})
      changeset = Permission.activate(permission)

      assert changeset.changes.is_active == true
    end

    test "deactivate/1 sets is_active to false" do
      permission = Factory.build_permission(%{is_active: true})
      changeset = Permission.deactivate(permission)

      assert changeset.changes.is_active == false
    end
  end

  describe "risk level determination" do
    test "assigns high risk to destructive actions" do
      destructive_actions = ~w(delete destroy remove purge)

      for action <- destructive_actions do
        changeset = Permission.new(%{resource: "posts", action: action})
        assert changeset.changes.risk_level == "high", "Action '#{action}' should be high risk"
      end
    end

    test "assigns medium risk to modification actions" do
      modification_actions = ~w(create update edit modify)

      for action <- modification_actions do
        changeset = Permission.new(%{resource: "posts", action: action})
        assert changeset.changes.risk_level == "medium", "Action '#{action}' should be medium risk"
      end
    end

    test "assigns critical risk to system resources" do
      system_resources = ~w(permissions roles system)

      for resource <- system_resources do
        changeset = Permission.new(%{resource: resource, action: "read"})
        assert changeset.changes.risk_level == "critical", "Resource '#{resource}' should be critical risk"
      end
    end

    test "assigns low risk to read actions" do
      read_actions = ~w(read view list show)

      for action <- read_actions do
        changeset = Permission.new(%{resource: "posts", action: action})
        assert changeset.changes.risk_level == "low", "Action '#{action}' should be low risk"
      end
    end
  end

  describe "category determination" do
    test "assigns correct categories based on resource" do
      test_cases = [
        {~w(users roles permissions), "identity"},
        {~w(posts articles comments), "content"},
        {~w(files documents images), "storage"},
        {~w(reports analytics dashboard), "analytics"},
        {~w(settings system audit_logs), "system"}
      ]

      for {resources, expected_category} <- test_cases do
        for resource <- resources do
          changeset = Permission.new(%{resource: resource, action: "read"})
          assert changeset.changes.category == expected_category,
            "Resource '#{resource}' should have category '#{expected_category}'"
        end
      end
    end

    test "assigns 'general' category for unknown resources" do
      changeset = Permission.new(%{resource: "unknown_resource", action: "read"})
      assert changeset.changes.category == "general"
    end
  end
end