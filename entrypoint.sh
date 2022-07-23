#!/usr/bin/env bash

# Create, migrate, and seed database if it doesn't exist.
echo "$(date) - run database migrations"
mix ecto.setup
echo "$(date) - start server"
exec mix phx.server