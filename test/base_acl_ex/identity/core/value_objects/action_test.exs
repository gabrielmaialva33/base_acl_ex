defmodule BaseAclEx.Identity.Core.ValueObjects.ActionTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Identity.Core.ValueObjects.Action
  alias BaseAclEx.TestSupport.TestHelpers
  import TestHelpers

  describe "new/1" do
    test "creates valid action value object for standard actions" do
      standard_actions = ["create", "read", "update", "delete", "list", "view"]

      for action_name <- standard_actions do
        assert {:ok, action} = Action.new(action_name)
        assert action.name == action_name
        assert action.type in ["crud", "read", "write"]
        assert action.risk_level in ["low", "medium", "high"]
      end
    end

    test "creates valid action for custom actions" do
      assert {:ok, action} = Action.new("custom_action")
      assert action.name == "custom_action"
      assert action.type == "custom"
      assert action.risk_level == "low"
    end

    test "normalizes action names" do
      test_cases = [
        {"CREATE", "create"},
        {"  read  ", "read"},
        {"Update-Item", "update_item"},
        {"Complex Action Name", "complex_action_name"},
        {"Action123", "action123"}
      ]

      for {input, expected} <- test_cases do
        assert {:ok, action} = Action.new(input)
        assert action.name == expected
      end
    end

    test "rejects invalid action names" do
      invalid_actions = [
        "",
        "   ",
        # starts with number
        "1action",
        # invalid character
        "action!",
        # too short
        "a",
        # too long
        String.duplicate("a", 31)
      ]

      for invalid_action <- invalid_actions do
        assert {:error, :invalid_action} = Action.new(invalid_action)
      end
    end

    test "rejects non-string inputs" do
      assert {:error, :invalid_action} = Action.new(123)
      assert {:error, :invalid_action} = Action.new(nil)
      assert {:error, :invalid_action} = Action.new(:atom)
      assert {:error, :invalid_action} = Action.new(["list"])
    end
  end

  describe "new!/1" do
    test "creates action value object for valid input" do
      action = Action.new!("read")
      assert action.name == "read"
    end

    test "raises for invalid action" do
      assert_raise ArgumentError, "Invalid action: invalid_action", fn ->
        Action.new!("invalid!")
      end
    end
  end

  describe "valid?/1" do
    test "validates standard actions" do
      standard_actions = [
        "create",
        "read",
        "update",
        "delete",
        "list",
        "view",
        "show",
        "index",
        "execute",
        "run",
        "process",
        "import",
        "export",
        "download",
        "upload"
      ]

      for action <- standard_actions do
        assert Action.valid?(action), "#{action} should be valid"
      end
    end

    test "validates custom actions with correct pattern" do
      valid_custom_actions = [
        "custom_action",
        "my_custom_action",
        "action123",
        "validate_email",
        "process_payment"
      ]

      for action <- valid_custom_actions do
        assert Action.valid?(action), "#{action} should be valid"
      end
    end

    test "rejects invalid actions" do
      invalid_actions = [
        "",
        "1action",
        "action!",
        "Action-Name",
        "UPPERCASE",
        String.duplicate("a", 31),
        nil,
        123
      ]

      for action <- invalid_actions do
        refute Action.valid?(action), "#{inspect(action)} should be invalid"
      end
    end
  end

  describe "normalize/1" do
    test "normalizes action names correctly" do
      test_cases = [
        {"CREATE", "create"},
        {"  Read  ", "read"},
        {"Update-Item", "update_item"},
        {"Complex Action Name!", "complex_action_name_"},
        {"Action123", "action123"},
        {"", ""}
      ]

      for {input, expected} <- test_cases do
        assert Action.normalize(input) == expected
      end
    end

    test "handles non-string inputs" do
      assert Action.normalize(nil) == ""
      assert Action.normalize(123) == ""
      assert Action.normalize(:atom) == ""
    end
  end

  describe "categorize_type/1" do
    test "categorizes CRUD actions" do
      crud_actions = ["create", "read", "update", "delete"]

      for action <- crud_actions do
        assert Action.categorize_type(action) == "crud"
      end
    end

    test "categorizes read actions" do
      read_actions = ["read", "list", "view", "show", "index", "search", "filter", "sort"]

      for action <- read_actions do
        result = Action.categorize_type(action)
        assert result in ["crud", "read"], "Action #{action} got type #{result}"
      end
    end

    test "categorizes write actions" do
      write_actions = ["create", "update", "delete", "import", "upload"]

      for action <- write_actions do
        result = Action.categorize_type(action)
        assert result in ["crud", "write"], "Action #{action} got type #{result}"
      end
    end

    test "categorizes admin actions" do
      admin_actions = ["grant", "revoke", "backup", "restore", "migrate", "audit"]

      for action <- admin_actions do
        assert Action.categorize_type(action) == "admin"
      end
    end

    test "categorizes custom actions" do
      assert Action.categorize_type("custom_action") == "custom"
      assert Action.categorize_type("unknown_action") == "custom"
    end

    test "handles invalid inputs" do
      assert Action.categorize_type(nil) == "unknown"
      assert Action.categorize_type(123) == "unknown"
    end
  end

  describe "assess_risk/1" do
    test "assigns low risk to read actions" do
      read_actions = ["read", "list", "view", "show", "index", "search"]

      for action <- read_actions do
        assert Action.assess_risk(action) == "low"
      end
    end

    test "assigns medium risk to modification actions" do
      medium_risk_actions = ["update", "edit", "modify", "create", "add", "insert"]

      for action <- medium_risk_actions do
        assert Action.assess_risk(action) == "medium"
      end
    end

    test "assigns high risk to destructive actions" do
      high_risk_actions = ["delete", "remove", "destroy"]

      for action <- high_risk_actions do
        assert Action.assess_risk(action) == "high"
      end
    end

    test "assigns critical risk to admin actions" do
      admin_actions = ["grant", "revoke", "backup", "restore", "migrate", "audit"]

      for action <- admin_actions do
        assert Action.assess_risk(action) == "critical"
      end
    end

    test "assigns low risk to unknown actions" do
      assert Action.assess_risk("custom_action") == "low"
      assert Action.assess_risk("unknown") == "low"
    end

    test "handles invalid inputs" do
      assert Action.assess_risk(nil) == "unknown"
      assert Action.assess_risk(123) == "unknown"
    end
  end

  describe "action classification predicates" do
    test "read_only?/1 identifies read-only actions" do
      read_only_actions = ["read", "list", "view", "show", "index", "search", "filter", "sort"]

      for action <- read_only_actions do
        assert Action.read_only?(action), "#{action} should be read-only"
      end

      non_read_actions = ["create", "update", "delete", "execute", "grant"]

      for action <- non_read_actions do
        refute Action.read_only?(action), "#{action} should not be read-only"
      end
    end

    test "modifies_data?/1 identifies data-modifying actions" do
      modifying_actions = ["create", "update", "delete", "import", "upload"]

      for action <- modifying_actions do
        assert Action.modifies_data?(action), "#{action} should modify data"
      end

      non_modifying_actions = ["read", "list", "view", "show"]

      for action <- non_modifying_actions do
        refute Action.modifies_data?(action), "#{action} should not modify data"
      end
    end

    test "administrative?/1 identifies admin actions" do
      admin_actions = ["grant", "revoke", "backup", "restore", "migrate", "audit"]

      for action <- admin_actions do
        assert Action.administrative?(action), "#{action} should be administrative"
      end

      regular_actions = ["create", "read", "update", "delete"]

      for action <- regular_actions do
        refute Action.administrative?(action), "#{action} should not be administrative"
      end
    end
  end

  describe "utility functions" do
    test "all_actions/0 returns list of valid actions" do
      actions = Action.all_actions()

      assert is_list(actions)
      assert length(actions) > 20
      assert "create" in actions
      assert "read" in actions
      assert "update" in actions
      assert "delete" in actions
    end

    test "crud_actions/0 returns CRUD actions" do
      crud_actions = Action.crud_actions()

      assert crud_actions == ["create", "read", "update", "delete"]
    end

    test "to_string/1 returns action name" do
      {:ok, action} = Action.new("read")
      assert Action.to_string(action) == "read"
    end
  end

  describe "String.Chars protocol" do
    test "implements to_string protocol" do
      {:ok, action} = Action.new("create")
      assert to_string(action) == "create"
    end

    test "can be used in string interpolation" do
      {:ok, action} = Action.new("update")
      message = "Performing #{action} operation"
      assert message == "Performing update operation"
    end
  end

  describe "integration scenarios" do
    test "action creation and classification workflow" do
      # Test various actions through the full workflow
      test_actions = [
        {"READ", "read", "read", "low"},
        {"Create-Item", "create_item", "custom", "low"},
        {"delete", "delete", "crud", "high"},
        {"GRANT_PERMISSION", "grant_permission", "custom", "low"},
        {"backup", "backup", "admin", "critical"}
      ]

      for {input, expected_name, expected_type, expected_risk} <- test_actions do
        {:ok, action} = Action.new(input)

        assert action.name == expected_name
        assert action.type == expected_type
        assert action.risk_level == expected_risk

        # Test string representation
        assert to_string(action) == expected_name
      end
    end

    test "action validation and security classification" do
      # High-risk actions should be properly identified
      high_risk_inputs = ["DELETE", "destroy", "remove"]

      for input <- high_risk_inputs do
        {:ok, action} = Action.new(input)
        assert action.risk_level in ["high", "critical"]
        refute Action.read_only?(action.name)
      end

      # Read-only actions should be low risk
      read_only_inputs = ["READ", "list", "view"]

      for input <- read_only_inputs do
        {:ok, action} = Action.new(input)
        assert action.risk_level == "low"
        assert Action.read_only?(action.name)
        refute Action.modifies_data?(action.name)
      end

      # Admin actions should be critical risk
      admin_inputs = ["grant", "revoke", "audit"]

      for input <- admin_inputs do
        {:ok, action} = Action.new(input)
        assert action.risk_level == "critical"
        assert Action.administrative?(action.name)
      end
    end

    test "custom action validation and normalization" do
      # Valid custom actions
      valid_customs = [
        "validate_email",
        "process_payment",
        "send_notification",
        "generate_report"
      ]

      for custom_action <- valid_customs do
        assert Action.valid?(custom_action)
        {:ok, action} = Action.new(custom_action)
        assert action.name == custom_action
        assert action.type == "custom"
        assert action.risk_level == "low"
      end

      # Invalid custom actions should be rejected
      invalid_customs = [
        "1invalid",
        "invalid!",
        "too-long-action-name-that-exceeds-limit",
        ""
      ]

      for invalid_action <- invalid_customs do
        refute Action.valid?(invalid_action)
        assert {:error, :invalid_action} = Action.new(invalid_action)
      end
    end
  end
end
