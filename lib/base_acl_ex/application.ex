defmodule BaseAclEx.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      BaseAclExWeb.Telemetry,
      BaseAclEx.Repo,
      {DNSCluster, query: Application.get_env(:base_acl_ex, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: BaseAclEx.PubSub},
      # Rate limiter cache (before other security services) - TEMPORARILY DISABLED
      # BaseAclEx.Infrastructure.Security.Cache.RateLimiterCache,
      # CQRS and Permission services (order matters for dependencies)
      BaseAclEx.Identity.Application.Services.PermissionCache,
      BaseAclEx.SharedKernel.CQRS.CommandBus,
      BaseAclEx.SharedKernel.CQRS.QueryBus,
      # Security workers
      BaseAclEx.Infrastructure.Security.Workers.TokenCleanupWorker,
      # Start to serve requests, typically the last entry
      BaseAclExWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: BaseAclEx.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    BaseAclExWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
