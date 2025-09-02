<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/gabrielmaialva33/base-acl-ex/master/.github/assets/logo.png" alt="BaseAclEx" width="200">
  <br>
  BaseAclEx 🔐
  <br>
</h1>

<p align="center">
  <strong>A high-performance, enterprise-grade Access Control List (ACL) system for Phoenix/Elixir applications</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/github/license/gabrielmaialva33/base-acl-ex?color=00b8d3?style=flat&logo=appveyor" alt="License" />
  <img src="https://img.shields.io/github/languages/top/gabrielmaialva33/base-acl-ex?style=flat&logo=appveyor" alt="GitHub top language" >
  <img src="https://img.shields.io/github/languages/count/gabrielmaialva33/base-acl-ex?style=flat&logo=appveyor" alt="GitHub language count" >
  <img src="https://img.shields.io/github/repo-size/gabrielmaialva33/base-acl-ex?style=flat&logo=appveyor" alt="Repository size" >
  <a href="https://github.com/gabrielmaialva33/base-acl-ex/commits/master">
    <img src="https://img.shields.io/github/last-commit/gabrielmaialva33/base-acl-ex?style=flat&logo=appveyor" alt="GitHub last commit" >
    <img src="https://img.shields.io/badge/made%20by-Maia-15c3d6?style=flat&logo=appveyor" alt="Maia" >  
  </a>
</p>

<br>

<p align="center">
  <a href="#bookmark-about">About</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
  <a href="#rocket-technologies">Technologies</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
  <a href="#boom-features">Features</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
  <a href="#wrench-installation">Installation</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
  <a href="#gear-configuration">Configuration</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
  <a href="#zap-api-documentation">API Documentation</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
  <a href="#memo-license">License</a>
</p>

<br>

## :bookmark: About

**BaseAclEx** is a comprehensive, production-ready Access Control List (ACL) system built with Phoenix Framework and Elixir. It provides a robust foundation for implementing fine-grained permission management in enterprise applications using Domain-Driven Design (DDD) principles, Command Query Responsibility Segregation (CQRS) pattern, and event sourcing capabilities.

The system is designed to handle complex authorization scenarios with high performance, featuring role-based access control (RBAC), hierarchical permissions, permission inheritance, and real-time permission updates through WebSocket support.

## 🎯 Project Vision

Provide a scalable, maintainable, and secure authorization system that can be easily integrated into any Phoenix application. The architecture supports multi-tenancy, permission delegation, audit trails, and compliance with enterprise security standards while maintaining the simplicity and elegance of Elixir.

<br>

## :rocket: Technologies

### Core Stack
- **[Elixir](https://elixir-lang.org/)** 1.15+ - A dynamic, functional language designed for building maintainable and scalable applications
- **[Phoenix Framework](https://www.phoenixframework.org/)** 1.8.1 - A productive web framework that does not compromise speed or maintainability
- **[PostgreSQL](https://www.postgresql.org/)** 14+ - The world's most advanced open source relational database
- **[Ecto](https://hexdocs.pm/ecto/Ecto.html)** - Database wrapper and query generator for Elixir

### Authentication & Security
- **[Guardian](https://github.com/ueberauth/guardian)** - JWT authentication library for Elixir
- **[Argon2](https://github.com/riverrun/argon2_elixir)** - Password hashing library
- **[Bodyguard](https://github.com/schrockwell/bodyguard)** - Authorization library for Phoenix

### Development & Quality
- **[Credo](https://github.com/rrrene/credo)** - Static code analysis tool for Elixir
- **[Dialyxir](https://github.com/jeremyjh/dialyxir)** - Static type checking
- **[ExUnit](https://hexdocs.pm/ex_unit/ExUnit.html)** - Unit testing framework
- **[Docker](https://www.docker.com/)** - Containerization platform

<br>

## :boom: Features

### ✅ **Authentication & User Management**
- JWT-based authentication with refresh tokens
- User registration with email verification
- Password reset functionality
- Two-factor authentication support
- Session management and device tracking
- Account lockout after failed attempts

### ✅ **Authorization System**
- **Role-Based Access Control (RBAC)**
  - Dynamic role creation and management
  - Role hierarchy with inheritance
  - System roles protection
  
- **Permission Management**
  - Resource-based permissions
  - Action-based permissions (CRUD operations)
  - Scoped permissions (own, team, global)
  - Permission inheritance through role hierarchy
  - Wildcard permissions support

### ✅ **Advanced ACL Features**
- **Permission Caching**
  - Redis-based permission caching
  - Automatic cache invalidation
  - Performance optimization for permission checks
  
- **Audit Logging**
  - Complete audit trail for all permission changes
  - User action tracking
  - Compliance-ready logging
  
- **Multi-tenancy Support**
  - Organization-based isolation
  - Cross-tenant permission management
  - Tenant-specific roles

### ✅ **Domain-Driven Design Architecture**
- **Bounded Contexts**
  - Accounts (User management)
  - Authorization (Roles & Permissions)
  - Identity (Authentication)
  - Audit (Logging & Compliance)
  
- **CQRS Implementation**
  - Command/Query separation
  - Event sourcing capabilities
  - Domain events handling
  
- **Clean Architecture**
  - Clear separation of concerns
  - Repository pattern
  - Use case driven development

### ✅ **REST API**
- **Versioned API (v1)**
  - RESTful endpoints
  - JSON responses
  - Pagination support
  - Filtering and sorting
  
- **API Features**
  - Rate limiting
  - Request validation
  - Error handling with fallback controller
  - OpenAPI/Swagger documentation

### ✅ **Developer Experience**
- Comprehensive test coverage
- Database migrations with rollback support
- Seed data for development
- Docker development environment
- Hot code reloading
- Interactive Elixir shell (IEx)

<br>

## 📊 System Architecture

### High-Level Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        Web[Web Client]
        Mobile[Mobile App]
        API[External API]
    end
    
    subgraph "API Gateway"
        Router[Phoenix Router]
        Auth[Authentication Middleware]
        RateLimit[Rate Limiter]
    end
    
    subgraph "Application Layer"
        Controllers[REST Controllers]
        WS[WebSocket Channels]
        Commands[Command Handlers]
        Queries[Query Handlers]
    end
    
    subgraph "Domain Layer"
        Accounts[Accounts Context]
        Authorization[Authorization Context]
        Identity[Identity Context]
        Audit[Audit Context]
    end
    
    subgraph "Infrastructure Layer"
        Repo[Ecto Repository]
        Cache[Redis Cache]
        EventBus[Event Bus]
        Mailer[Email Service]
    end
    
    subgraph "Data Layer"
        PG[(PostgreSQL)]
        Redis[(Redis)]
    end
    
    Web --> Router
    Mobile --> Router
    API --> Router
    
    Router --> Auth
    Auth --> RateLimit
    RateLimit --> Controllers
    RateLimit --> WS
    
    Controllers --> Commands
    Controllers --> Queries
    
    Commands --> Accounts
    Commands --> Authorization
    Queries --> Identity
    Queries --> Audit
    
    Accounts --> Repo
    Authorization --> Cache
    Identity --> EventBus
    Audit --> Mailer
    
    Repo --> PG
    Cache --> Redis
```

### Database Schema

```mermaid
erDiagram
    users ||--o{ user_roles : has
    users ||--o{ user_permissions : has
    users ||--o{ audit_logs : generates
    users ||--o{ sessions : has
    
    roles ||--o{ user_roles : belongs
    roles ||--o{ role_permissions : has
    roles ||--o{ role_hierarchy : parent
    roles ||--o{ role_hierarchy : child
    
    permissions ||--o{ user_permissions : assigned
    permissions ||--o{ role_permissions : assigned
    
    users {
        uuid id PK
        string email UK
        string username UK
        string password_hash
        string first_name
        string last_name
        string phone_number
        timestamp email_verified_at
        timestamp locked_at
        timestamp deleted_at
        boolean two_factor_enabled
        integer failed_attempts
        jsonb metadata
    }
    
    roles {
        uuid id PK
        string name UK
        string slug UK
        string description
        integer priority
        boolean is_system
        jsonb metadata
        timestamp deleted_at
    }
    
    permissions {
        uuid id PK
        string name UK
        string slug UK
        string resource
        string action
        string scope
        string description
        boolean is_system
        jsonb metadata
        timestamp deleted_at
    }
    
    user_roles {
        uuid id PK
        uuid user_id FK
        uuid role_id FK
        uuid assigned_by FK
        timestamp expires_at
        timestamp revoked_at
        string reason
    }
    
    role_permissions {
        uuid id PK
        uuid role_id FK
        uuid permission_id FK
        uuid granted_by FK
        timestamp revoked_at
        string reason
    }
    
    user_permissions {
        uuid id PK
        uuid user_id FK
        uuid permission_id FK
        uuid granted_by FK
        timestamp expires_at
        timestamp revoked_at
        string reason
    }
    
    role_hierarchy {
        uuid id PK
        uuid parent_role_id FK
        uuid child_role_id FK
        boolean inherit_permissions
    }
    
    audit_logs {
        uuid id PK
        uuid user_id FK
        string action
        string resource_type
        uuid resource_id
        jsonb old_values
        jsonb new_values
        string ip_address
        string user_agent
        timestamp created_at
    }
    
    sessions {
        uuid id PK
        uuid user_id FK
        string token_hash UK
        string ip_address
        string user_agent
        timestamp expires_at
        timestamp last_activity_at
    }
```

<br>

## :wrench: Installation

### Prerequisites

Ensure you have the following installed:
- **[Elixir](https://elixir-lang.org/install.html)** ~> 1.15
- **[Erlang/OTP](https://www.erlang.org/downloads)** ~> 26
- **[PostgreSQL](https://www.postgresql.org/download/)** >= 14
- **[Redis](https://redis.io/download)** >= 6 (optional, for caching)
- **[Node.js](https://nodejs.org/)** >= 18 (for assets)
- **[Docker](https://docs.docker.com/get-docker/)** (optional)

### Clone the Repository

```bash
# Clone the repository
git clone https://github.com/gabrielmaialva33/base-acl-ex.git
cd base-acl-ex

# Install dependencies
mix setup
```

### Docker Setup (Recommended)

```bash
# Start all services
docker-compose up -d

# Create and migrate database
docker-compose exec app mix ecto.setup

# Run the application
docker-compose exec app mix phx.server
```

### Manual Setup

```bash
# Install dependencies
mix deps.get

# Create and migrate database
mix ecto.create
mix ecto.migrate

# Install Node.js dependencies
cd assets && npm install && cd ..

# Start Phoenix server
mix phx.server

# Or run in interactive mode
iex -S mix phx.server
```

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

<br>

## :gear: Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Database Configuration
DATABASE_URL=ecto://postgres:postgres@localhost/base-acl-ex_dev
DATABASE_POOL_SIZE=10

# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379

# Guardian Secret Key
GUARDIAN_SECRET_KEY=your_secret_key_here

# Application
PHX_HOST=localhost
PHX_PORT=4000
SECRET_KEY_BASE=your_secret_key_base_here

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_password
```

### Database Migrations

```bash
# Run migrations
mix ecto.migrate

# Rollback migrations
mix ecto.rollback

# Create a new migration
mix ecto.gen.migration migration_name

# Seed the database
mix run priv/repo/seeds.exs
```

### Development Commands

```bash
# Run tests
mix test

# Run tests with coverage
mix test --cover

# Run Credo for code analysis
mix credo --strict

# Run format check
mix format --check-formatted

# Run dialyzer for type checking
mix dialyzer

# Run all quality checks
mix precommit
```

<br>

## :zap: API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

#### Refresh Token
```http
POST /api/v1/auth/refresh
Authorization: Bearer <refresh_token>
```

### User Management

#### List Users
```http
GET /api/v1/users?page=1&per_page=20&search=john
Authorization: Bearer <access_token>
```

#### Get User Details
```http
GET /api/v1/users/:id
Authorization: Bearer <access_token>
```

#### Update User
```http
PUT /api/v1/users/:id
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "first_name": "Jane",
  "last_name": "Smith"
}
```

### Role Management

#### List Roles
```http
GET /api/v1/roles
Authorization: Bearer <access_token>
```

#### Create Role
```http
POST /api/v1/roles
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Editor",
  "slug": "editor",
  "description": "Can edit content",
  "priority": 50
}
```

#### Assign Role to User
```http
POST /api/v1/roles/:role_id/users/:user_id
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "reason": "Promoted to editor",
  "expires_at": "2024-12-31T23:59:59Z"
}
```

### Permission Management

#### List Permissions
```http
GET /api/v1/permissions?resource=posts&action=read
Authorization: Bearer <access_token>
```

#### Create Permission
```http
POST /api/v1/permissions
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Read Posts",
  "slug": "read_posts",
  "resource": "posts",
  "action": "read",
  "scope": "own"
}
```

#### Check User Permissions
```http
GET /api/v1/users/:id/permissions
Authorization: Bearer <access_token>
```

### Response Format

All API responses follow a consistent format:

#### Success Response
```json
{
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

#### Error Response
```json
{
  "error": {
    "message": "Invalid credentials",
    "code": "INVALID_CREDENTIALS"
  }
}
```

#### Paginated Response
```json
{
  "data": [...],
  "meta": {
    "current_page": 1,
    "per_page": 20,
    "total_pages": 5,
    "total_entries": 100
  }
}
```

<br>

## 🗂️ Project Structure

```
base-acl-ex/
├── config/                 # Application configuration
│   ├── config.exs         # Main configuration
│   ├── dev.exs            # Development environment
│   ├── prod.exs           # Production environment
│   └── test.exs           # Test environment
├── lib/
│   ├── base_acl_ex/       # Business logic
│   │   ├── accounts/      # Accounts bounded context
│   │   │   ├── application/   # Application services
│   │   │   │   ├── commands/  # Command handlers
│   │   │   │   ├── queries/   # Query handlers
│   │   │   │   └── handlers/  # Business logic handlers
│   │   │   ├── core/          # Domain layer
│   │   │   │   ├── entities/  # Domain entities
│   │   │   │   ├── value_objects/ # Value objects
│   │   │   │   └── aggregates/    # Aggregates
│   │   │   └── infrastructure/    # Infrastructure layer
│   │   ├── authorization/  # Authorization context
│   │   │   ├── core/
│   │   │   └── policies/
│   │   ├── identity/       # Identity & authentication
│   │   │   ├── application/
│   │   │   └── core/
│   │   ├── audit/          # Audit logging
│   │   │   └── services/
│   │   ├── shared_kernel/  # Shared domain concepts
│   │   │   ├── cqrs/       # CQRS infrastructure
│   │   │   └── events/     # Domain events
│   │   └── infrastructure/ # Technical infrastructure
│   │       ├── persistence/   # Database repositories
│   │       ├── security/      # Security implementations
│   │       └── cache/         # Caching layer
│   └── base_acl_ex_web/   # Web layer
│       ├── controllers/    # HTTP controllers
│       │   └── api/        # API controllers
│       │       └── v1/     # Version 1 API
│       ├── channels/       # WebSocket channels
│       ├── formatters/     # Response formatters
│       ├── plugs/          # Custom plugs
│       └── router.ex       # Route definitions
├── priv/
│   ├── repo/              # Database related files
│   │   ├── migrations/    # Database migrations
│   │   └── seeds.exs      # Seed data
│   └── static/            # Static assets
├── test/                  # Test files
│   ├── base_acl_ex/       # Business logic tests
│   ├── base_acl_ex_web/   # Web layer tests
│   └── support/           # Test helpers
├── .github/               # GitHub specific files
│   ├── workflows/         # CI/CD pipelines
│   └── assets/            # Repository assets
├── docker-compose.yml     # Docker services configuration
├── Dockerfile             # Application container
├── mix.exs                # Project configuration
└── README.md              # This file
```

<br>

## 🧪 Testing

The project includes comprehensive test coverage:

```bash
# Run all tests
mix test

# Run specific test file
mix test test/base_acl_ex/accounts/user_test.exs

# Run tests with coverage
mix test --cover

# Run tests in watch mode
mix test.watch

# Run integration tests
mix test --only integration

# Run unit tests only
mix test --only unit
```

### Test Structure

```
test/
├── base_acl_ex/
│   ├── accounts/          # Account context tests
│   ├── authorization/     # Authorization tests
│   └── identity/          # Identity tests
├── base_acl_ex_web/
│   ├── controllers/       # Controller tests
│   └── channels/          # Channel tests
└── support/
    ├── channel_case.ex    # Channel test helpers
    ├── conn_case.ex       # Controller test helpers
    └── data_case.ex       # Database test helpers
```

<br>

## 📈 Performance

### Optimization Strategies

- **Permission Caching**: Redis-based caching with automatic invalidation
- **Database Indexing**: Optimized indexes for common queries
- **Query Optimization**: N+1 query prevention with preloading
- **Connection Pooling**: Configurable database connection pools
- **Async Processing**: Background jobs for heavy operations

### Benchmarks

```bash
# Run benchmarks
mix run benchmarks/permission_check.exs

# Expected results (example)
Permission Check: 0.5ms average
Role Assignment: 2ms average
Cache Hit Rate: 95%+
```

<br>

## 🚀 Deployment

### Production Configuration

```elixir
# config/prod.exs
config :base-acl-ex, BaseAclExWeb.Endpoint,
  url: [host: "your-domain.com", port: 443],
  https: [
    port: 443,
    cipher_suite: :strong,
    keyfile: System.get_env("SSL_KEY_PATH"),
    certfile: System.get_env("SSL_CERT_PATH")
  ]
```

### Docker Production Build

```bash
# Build production image
docker build -t base_acl_ex:latest .

# Run with environment variables
docker run -d \
  -e DATABASE_URL=$DATABASE_URL \
  -e SECRET_KEY_BASE=$SECRET_KEY_BASE \
  -e GUARDIAN_SECRET_KEY=$GUARDIAN_SECRET_KEY \
  -p 4000:4000 \
  base_acl_ex:latest
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: base-acl-ex
spec:
  replicas: 3
  selector:
    matchLabels:
      app: base-acl-ex
  template:
    metadata:
      labels:
        app: base-acl-ex
    spec:
      containers:
      - name: app
        image: base_acl_ex:latest
        ports:
        - containerPort: 4000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
```

<br>

## 📋 Roadmap

### Phase 1: Core Features ✅
- [x] User authentication with JWT
- [x] Role-based access control
- [x] Permission management
- [x] REST API v1
- [x] Database migrations
- [x] Docker support

### Phase 2: Advanced Features 🚧
- [ ] GraphQL API support
- [ ] WebSocket real-time updates
- [ ] Advanced audit logging
- [ ] Permission delegation
- [ ] API rate limiting
- [ ] OpenAPI/Swagger documentation

### Phase 3: Enterprise Features 📋
- [ ] SAML/OAuth2 integration
- [ ] Multi-factor authentication
- [ ] Permission templates
- [ ] Compliance reporting
- [ ] Advanced analytics
- [ ] Horizontal scaling support

<br>

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- Follow Elixir style guide
- Write tests for new features
- Update documentation
- Run `mix credo --strict` before committing
- Ensure all tests pass

<br>

## :writing_hand: **Author**

| [![Gabriel Maia](https://avatars.githubusercontent.com/u/26732067?size=100)](https://github.com/gabrielmaialva33) |
|-------------------------------------------------------------------------------------------------------------------|
| [Gabriel Maia](https://github.com/gabrielmaialva33)                                                               |

## :handshake: **Contributors**

| [![Contributors](https://contrib.rocks/image?repo=gabrielmaialva33/base_acl_ex)](https://github.com/gabrielmaialva33/base_acl_ex/graphs/contributors) |
|---------------------------------------------------------------------------------------------------------------------------------------------------------|

<br>

## :memo: License

This project is under the MIT license. See the [LICENSE](LICENSE) file for more details.

---

<p align="center">
  Made with :heart: by <a href="https://github.com/gabrielmaialva33">Gabriel Maia</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/gabrielmaialva33/gabrielmaialva33/master/assets/gray0_ctp_on_line.svg?sanitize=true" />
</p>

<p align="center">
  &copy; 2024-present <a href="https://github.com/gabrielmaialva33/" target="_blank">Gabriel Maia</a>
</p>