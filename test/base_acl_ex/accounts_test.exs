defmodule BaseAclEx.AccountsTest do
  use BaseAclEx.DataCase

  alias BaseAclEx.Accounts

  describe "users" do
    alias BaseAclEx.Accounts.User

    import BaseAclEx.AccountsFixtures

    @invalid_attrs %{
      email: nil,
      firstname: nil,
      is_deleted: nil,
      lastname: nil,
      password_hash: nil,
      username: nil
    }

    test "list_users/0 returns all users" do
      user = user_fixture()
      assert Accounts.list_users() == [user]
    end

    test "get_user!/1 returns the user with given id" do
      user = user_fixture()
      assert Accounts.get_user!(user.id) == user
    end

    test "create_user/1 with valid data creates a user" do
      valid_attrs = %{
        email: "some email",
        firstname: "some firstname",
        is_deleted: true,
        lastname: "some lastname",
        password_hash: "some password_hash",
        username: "some username"
      }

      assert {:ok, %User{} = user} = Accounts.create_user(valid_attrs)
      assert user.email == "some email"
      assert user.firstname == "some firstname"
      assert user.is_deleted == true
      assert user.lastname == "some lastname"
      assert user.password_hash == "some password_hash"
      assert user.username == "some username"
    end

    test "create_user/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Accounts.create_user(@invalid_attrs)
    end

    test "update_user/2 with valid data updates the user" do
      user = user_fixture()

      update_attrs = %{
        email: "some updated email",
        firstname: "some updated firstname",
        is_deleted: false,
        lastname: "some updated lastname",
        password_hash: "some updated password_hash",
        username: "some updated username"
      }

      assert {:ok, %User{} = user} = Accounts.update_user(user, update_attrs)
      assert user.email == "some updated email"
      assert user.firstname == "some updated firstname"
      assert user.is_deleted == false
      assert user.lastname == "some updated lastname"
      assert user.password_hash == "some updated password_hash"
      assert user.username == "some updated username"
    end

    test "update_user/2 with invalid data returns error changeset" do
      user = user_fixture()
      assert {:error, %Ecto.Changeset{}} = Accounts.update_user(user, @invalid_attrs)
      assert user == Accounts.get_user!(user.id)
    end

    test "delete_user/1 deletes the user" do
      user = user_fixture()
      assert {:ok, %User{}} = Accounts.delete_user(user)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_user!(user.id) end
    end

    test "change_user/1 returns a user changeset" do
      user = user_fixture()
      assert %Ecto.Changeset{} = Accounts.change_user(user)
    end
  end

  describe "roles" do
    alias BaseAclEx.Accounts.Role

    import BaseAclEx.AccountsFixtures

    @invalid_attrs %{description: nil, name: nil, slug: nil}

    test "list_roles/0 returns all roles" do
      role = role_fixture()
      assert Accounts.list_roles() == [role]
    end

    test "get_role!/1 returns the role with given id" do
      role = role_fixture()
      assert Accounts.get_role!(role.id) == role
    end

    test "create_role/1 with valid data creates a role" do
      valid_attrs = %{description: "some description", name: "some name", slug: "some slug"}

      assert {:ok, %Role{} = role} = Accounts.create_role(valid_attrs)
      assert role.description == "some description"
      assert role.name == "some name"
      assert role.slug == "some slug"
    end

    test "create_role/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Accounts.create_role(@invalid_attrs)
    end

    test "update_role/2 with valid data updates the role" do
      role = role_fixture()

      update_attrs = %{
        description: "some updated description",
        name: "some updated name",
        slug: "some updated slug"
      }

      assert {:ok, %Role{} = role} = Accounts.update_role(role, update_attrs)
      assert role.description == "some updated description"
      assert role.name == "some updated name"
      assert role.slug == "some updated slug"
    end

    test "update_role/2 with invalid data returns error changeset" do
      role = role_fixture()
      assert {:error, %Ecto.Changeset{}} = Accounts.update_role(role, @invalid_attrs)
      assert role == Accounts.get_role!(role.id)
    end

    test "delete_role/1 deletes the role" do
      role = role_fixture()
      assert {:ok, %Role{}} = Accounts.delete_role(role)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_role!(role.id) end
    end

    test "change_role/1 returns a role changeset" do
      role = role_fixture()
      assert %Ecto.Changeset{} = Accounts.change_role(role)
    end
  end
end
