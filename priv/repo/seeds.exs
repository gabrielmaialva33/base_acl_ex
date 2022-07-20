# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# Inside the script, you can read and write to any of your
# repositories directly:
#
#     BaseAclEx.Repo.insert!(%BaseAclEx.SomeSchema{})
#
# We recommend using the bang functions (`insert!`, `update!`
# and so on) as they will fail if something goes wrong.
alias BaseAclEx.Repo
alias BaseAclEx.Accounts.Models.Role

# Delete all existing roles
Repo.delete_all(Role)

# Seeding roles from the database
BaseAclEx.Repo.insert!(%Role{slug: "Root", name: "root", description: "a root system user"})
BaseAclEx.Repo.insert!(%Role{slug: "Admin", name: "admin", description: "a admin system user"})
BaseAclEx.Repo.insert!(%Role{slug: "User", name: "user", description: "a user system user"})
