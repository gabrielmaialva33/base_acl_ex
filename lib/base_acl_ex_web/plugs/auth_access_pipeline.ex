defmodule BaseAclExWeb.Plugs.AuthAccessPipeline do
  use Guardian.Plug.Pipeline,
    otp_app: :base_acl_ex,
    module: BaseAclEx.Guardian,
    error_handler: BaseAclExWeb.Plugs.AuthErrorHandler

  plug Guardian.Plug.VerifyHeader, scheme: "Bearer"
  plug Guardian.Plug.EnsureAuthenticated
  plug Guardian.Plug.LoadResource, allow_blank: true
end
