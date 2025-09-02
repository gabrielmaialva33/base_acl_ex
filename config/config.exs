# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :base_acl_ex,
  ecto_repos: [BaseAclEx.Repo],
  generators: [timestamp_type: :utc_datetime]

# Configures the endpoint
config :base_acl_ex, BaseAclExWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: BaseAclExWeb.ErrorHTML, json: BaseAclExWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: BaseAclEx.PubSub,
  # LiveView signing salt will be configured in runtime.exs from environment variables
  live_view: []

# Configures the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :base_acl_ex, BaseAclEx.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  base_acl_ex: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.1.7",
  base_acl_ex: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Guardian configuration for JWT authentication
# Secret key will be configured in runtime.exs from environment variables
config :base_acl_ex, BaseAclEx.Infrastructure.Security.JWT.GuardianImpl,
  issuer: "base_acl_ex",
  allowed_algos: ["HS256", "RS256"],
  verify_issuer: true

# ttl and secret_key will be configured in environment-specific files

# Rate limiting configuration
config :base_acl_ex,
  # Enable/disable rate limiting globally
  rate_limiting_enabled: true,
  # Enable logging of rate limit events
  rate_limiting_log_enabled: false,
  # Rate limiter cache configuration
  rate_limiter_cache: [
    # Max cache entries
    limit: 100_000,
    # 5 minutes
    cleanup_interval: 300_000
  ]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
