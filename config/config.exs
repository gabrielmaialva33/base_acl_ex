# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :base_acl_ex,
  ecto_repos: [BaseAclEx.Repo],
  generators: [binary_id: true]

# Configures the endpoint
config :base_acl_ex, BaseAclExWeb.Endpoint,
  url: [host: "localhost"],
  render_errors: [view: BaseAclExWeb.ErrorView, accepts: ~w(json), layout: false],
  pubsub_server: BaseAclEx.PubSub,
  live_view: [signing_salt: "e/R8PTch"]

# Configures the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :base_acl_ex, BaseAclEx.Mailer, adapter: Swoosh.Adapters.Local

# Swoosh API client is needed for adapters other than SMTP.
config :swoosh, :api_client, false

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

config :base_acl_ex, BaseAclEx.Guardian,
  issuer: "base_acl_ex",
  ttl: {30, :days},
  allowed_drift: 2000,
  secret_key: "fRK+MLCXJyIiSYv3y7bVk5YZxUO5WDexwuu2uhKjyVbn5NcZZBXhNlKFC2qPVhpW",
  serializer: BaseAclExWeb.Views.TokenView

# Use Flop for pagination in Phoenix
config :flop, repo: BaseAclEx.Repo

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
