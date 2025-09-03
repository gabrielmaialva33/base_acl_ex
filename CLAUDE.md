# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Phoenix web application (v1.8.1) using:

- Elixir ~> 1.15
- Phoenix LiveView ~> 1.1.0
- Ecto with PostgreSQL
- Tailwind CSS v4.1.7 (no config file needed)
- ESBuild for JavaScript bundling
- Bandit web server

## Common Development Commands

```bash
# Initial setup
mix setup                    # Install deps, create DB, run migrations, build assets

# Development server
mix phx.server              # Start Phoenix server on localhost:4000
iex -S mix phx.server       # Start server in interactive shell

# Database operations
mix ecto.create             # Create database
mix ecto.migrate            # Run pending migrations
mix ecto.reset              # Drop, create, and migrate database
mix ecto.rollback           # Rollback last migration

# Testing
mix test                    # Run all tests
mix test test/path/to/test.exs  # Run specific test file
mix test --failed           # Run previously failed tests

# Code quality checks
mix format                  # Format code
mix compile --warning-as-errors  # Compile with warnings as errors
mix deps.unlock --unused    # Check for unused dependencies

# Pre-commit checks (runs all quality checks)
mix precommit               # Runs: compile --warning-as-errors, deps.unlock --unused, format, test

# Asset building
mix assets.build            # Build CSS and JS assets
mix assets.deploy           # Build minified assets for production
```

## Architecture Overview

### Application Structure

The application follows standard Phoenix 1.8 conventions with clear separation between web and business logic:

- **`lib/base_acl_ex/`**: Core business logic and data layer
    - `application.ex`: OTP application supervisor tree configuration
    - `repo.ex`: Ecto repository for database operations
    - `mailer.ex`: Email delivery configuration (using Swoosh)

- **`lib/base_acl_ex_web/`**: Web layer (controllers, views, LiveViews)
    - `router.ex`: HTTP request routing with pipelines for browser and API
    - `endpoint.ex`: Phoenix endpoint configuration
    - `components/`: Reusable UI components
        - `core_components.ex`: Standard Phoenix components (forms, inputs, icons)
        - `layouts.ex`: Application layouts with flash message handling
    - `controllers/`: Traditional Phoenix controllers
    - LiveViews are placed directly in `lib/base_acl_ex_web/live/`

### Key Architectural Patterns

1. **Phoenix 1.8 Component System**: Uses function components with HEEx templates. The `core_components.ex` provides
   pre-built components like `<.input>`, `<.form>`, and `<.icon>`.

2. **Layout Wrapping**: All LiveView templates must begin with `<Layouts.app flash={@flash}>` wrapper.

3. **HTTP Client**: Uses Req library (already included) for HTTP requests - avoid HTTPoison or Tesla.

4. **Asset Pipeline**:
    - Tailwind CSS v4 with new import syntax (no config file)
    - ESBuild for JavaScript bundling
    - All assets must be imported through app.js/app.css

5. **Development Tools**:
    - LiveDashboard available at `/dev/dashboard` in development
    - Swoosh mailbox preview at `/dev/mailbox` in development

## Project-Specific Guidelines

### Phoenix v1.8 Specifics

- Flash messages are handled by `<.flash_group>` in the Layouts module only
- Use `<.link navigate={}>` and `<.link patch={}>` instead of deprecated `live_redirect`/`live_patch`
- Forms use `Phoenix.Component.form/1` with `to_form/2` - never use deprecated `Phoenix.HTML.form_for`
- Router scopes provide module aliasing - no need for additional aliases in route definitions

### Testing Approach

- Uses ExUnit with Phoenix test helpers
- LazyHTML library available for LiveView testing
- Test files in `test/` mirror the `lib/` structure
- ConnCase and DataCase support modules for test setup

### Code Style

- Run `mix precommit` before committing changes to ensure code quality
- Formatter configuration in `.formatter.exs` includes Phoenix.LiveView.HTMLFormatter
- Always use pattern matching and pipelines for idiomatic Elixir code

## Critical Reminders

1. **Elixir lists don't support index access** - use `Enum.at/2` instead
2. **Variables are immutable** - rebind results of block expressions
3. **HEEx requires `{...}` for attributes** and `<%= ... %>` for block constructs in tag bodies
4. **Never nest multiple modules** in the same file
5. **Always preload Ecto associations** when accessing them in templates
6. **Use LiveView streams** for collections to avoid memory issues
7. **Tailwind v4 doesn't need tailwind.config.js** - uses new import syntax in app.css

## Docker Development Commands

The project includes Docker and Docker Compose configurations for easy development and production deployment.

### Docker Compose Commands

```bash
# Start only PostgreSQL (for local development)
docker-compose up postgres

# Start all services (PostgreSQL + Redis)
docker-compose --profile dev up

# Start full stack including the Phoenix app
docker-compose --profile full up

# Build and start all services
docker-compose --profile full up --build

# Start services in background
docker-compose --profile full up -d

# Stop all services
docker-compose down

# Stop and remove volumes (clean state)
docker-compose down -v

# View logs from all services
docker-compose logs

# View logs from specific service
docker-compose logs app
docker-compose logs postgres
```

### Docker Build Commands

```bash
# Build the Phoenix application image
docker build -t base_acl_ex .

# Build with specific tag
docker build -t base_acl_ex:v1.0.0 .

# Build for production with build args
docker build --build-arg MIX_ENV=prod -t base_acl_ex:prod .

# Run the built image
docker run -p 4000:4000 --env-file .env.docker base_acl_ex

# Run with interactive terminal
docker run -it -p 4000:4000 --env-file .env.docker base_acl_ex /bin/bash
```

### Development Workflow with Docker

1. **Initial setup:**
   ```bash
   # Start database services
   docker-compose up postgres redis -d
   
   # Run migrations on local Elixir
   mix ecto.create
   mix ecto.migrate
   
   # Start Phoenix locally
   mix phx.server
   ```

2. **Full containerized development:**
   ```bash
   # Build and start everything
   docker-compose --profile full up --build
   
   # Access the application at http://localhost:4000
   ```

3. **Database operations with Docker:**
   ```bash
   # Access PostgreSQL container
   docker-compose exec postgres psql -U postgres -d base_acl_ex_dev
   
   # Backup database
   docker-compose exec postgres pg_dump -U postgres base_acl_ex_dev > backup.sql
   
   # Restore database
   docker-compose exec -T postgres psql -U postgres base_acl_ex_dev < backup.sql
   ```

### Environment Configuration

- **`.env.example`**: Template for local environment variables
- **`.env.docker`**: Docker-specific environment configuration
- **`docker-compose.yml`**: Multi-service orchestration with profiles

### Docker Image Optimization

The Dockerfile uses multi-stage builds to create optimized production images:

- **Builder stage**: Full Elixir environment for compilation
- **Runner stage**: Minimal Debian slim with only runtime dependencies
- **Final image size**: ~40-50MB (vs 200MB+ single-stage)
- **Security**: Non-root user, minimal attack surface

### Production Deployment

```bash
# Build production image
docker build --target runner --build-arg MIX_ENV=prod -t base_acl_ex:prod .

# Run production container
docker run -d \
  --name base_acl_ex_prod \
  -p 4000:4000 \
  --env-file .env.production \
  base_acl_ex:prod
```