defmodule BaseAclEx.Repo do
  use Ecto.Repo,
    otp_app: :base_acl_ex,
    adapter: Ecto.Adapters.Postgres
end
