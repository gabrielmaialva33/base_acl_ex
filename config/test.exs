import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :base_acl_ex, BaseAclEx.Repo,
  username: System.get_env("DB_USERNAME", "postgres"),
  password: System.get_env("DB_PASSWORD", "postgres"),
  hostname: System.get_env("DB_HOSTNAME", "localhost"),
  database:
    System.get_env("DB_DATABASE", "base_acl_ex_test") <> "#{System.get_env("MIX_TEST_PARTITION")}",
  port: System.get_env("DB_PORT", "5432") |> String.to_integer(),
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :base_acl_ex, BaseAclExWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base:
    System.get_env("SECRET_KEY_BASE") ||
      "LAKR3//wp8TvSbRNmhCAMhs5r950TKaebPSxd+204vNy//rCKD0BUuIgBmkYeJqM",
  live_view: [signing_salt: System.get_env("LIVEVIEW_SIGNING_SALT") || "test_salt"],
  server: false

# In test we don't send emails
config :base_acl_ex, BaseAclEx.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Guardian test configuration
config :base_acl_ex, BaseAclEx.Infrastructure.Security.JWT.GuardianImpl,
  secret_key:
    System.get_env("GUARDIAN_SECRET_KEY") || "test_guardian_secret_key_change_in_production",
  ttl: {String.to_integer(System.get_env("JWT_ACCESS_TOKEN_TTL_MINUTES") || "15"), :minutes}

# Rate limiting configuration for testing
# Disable rate limiting by default in tests to avoid interference
config :base_acl_ex,
  rate_limiting_enabled:
    String.to_existing_atom(System.get_env("RATE_LIMITING_ENABLED") || "false"),
  rate_limiting_log_enabled: false,
  rate_limiter_cache: [
    # Small cache for tests
    limit: 1_000,
    # 30 seconds
    cleanup_interval: 30_000
  ]
