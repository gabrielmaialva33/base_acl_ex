defmodule BaseAclEx.Infrastructure.Security.JWT.GuardianPipeline do
  @moduledoc """
  Guardian pipeline for handling JWT authentication in Phoenix.
  Provides plugs for authentication and authorization.
  """
  
  use Guardian.Plug.Pipeline,
    otp_app: :base_acl_ex,
    error_handler: BaseAclEx.Infrastructure.Security.JWT.GuardianErrorHandler,
    module: BaseAclEx.Infrastructure.Security.JWT.GuardianImpl
  
  # Plugs for authentication pipeline
  plug Guardian.Plug.VerifyHeader, scheme: "Bearer"
  plug Guardian.Plug.LoadResource, allow_blank: true
end