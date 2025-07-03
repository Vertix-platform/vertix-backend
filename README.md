# backend

```node
vertix-backend/
├── src/
│   ├── api/                    # API layer
│   ├── application/            # Application layer
│   ├── bin/
│   │   └── main.rs            # Binary entry point
│   ├── domain/
│   │   ├── mod.rs
│   │   ├── models.rs          # Domain models
│   │   └── services.rs        # Domain services
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── routes.rs          # Route handlers
│   ├── infrastructure/
│   │   ├── db/
│   │   │   ├── mod.rs
│   │   │   └── postgres.rs    # PostgreSQL implementation
│   │   ├── mod.rs
│   │   └── repositories/
│   │       ├── mod.rs
│   │       └── user_repository.rs  # User repository
│   └── lib.rs                 # Library entry point
├── migrations/
│   └── 20250515153322_create_table.sql  # Database migrations
├── tests/                     # Test files
├── .env                       # Environment variables
├── schema.sql                 # Database schema
├── Cargo.toml                 # Dependencies
└── Cargo.lock                 # Dependency lock file
```

## Directory Structure Details

### Core Architecture Layers

#### `src/domain/` - Domain Layer (Business Logic Core)

- **Purpose**: Contains the core business logic and domain models
- **Responsibilities**:
  - `models.rs`: Pure business entities (User, SocialMediaLink, etc.)
  - `services.rs`: Domain services and business rules
  - Independent of external frameworks and databases
  - Defines interfaces that outer layers must implement

#### `src/application/` - Application Layer (Use Cases)

- **Purpose**: Orchestrates domain objects to fulfill application use cases
- **Responsibilities**:
  - Application services that coordinate domain operations
  - Use case implementations (login, connect wallet, link social media)
  - Transaction boundaries and workflow orchestration
  - Depends on domain layer, independent of infrastructure

#### `src/infrastructure/` - Infrastructure Layer (External Concerns)

- **Purpose**: Implements external dependencies and technical details
- **Responsibilities**:
  - `db/`: Database connection and query implementations
    - `postgres.rs`: PostgreSQL-specific database operations
  - `repositories/`: Data access layer implementations
    - `user_repository.rs`: User data persistence logic
  - External API integrations, file systems, message queues

#### `src/api/` - API Layer (HTTP Interface)

- **Purpose**: Handles HTTP requests and responses
- **Responsibilities**:
  - REST API endpoint definitions
  - Request/response serialization
  - API versioning and documentation
  - OpenAPI/Swagger specifications

### Support Modules

#### `src/handlers/` - Request Handlers

- **Purpose**: HTTP request processing and routing logic
- **Responsibilities**:
  - `routes.rs`: Route configuration and handler registration
  - `user_handlers.rs`: User-specific endpoint implementations
  - Request validation and response formatting
  - HTTP-specific error handling

### Legacy/Transitional Files

#### Root `src/` Files

- `lib.rs`: Library interface for the crate

### External Directories

#### `migrations/` - Database Migrations

- **Purpose**: Version-controlled database schema changes
- **Contents**: SQL migration files with timestamps
- **Usage**: Applied in order to evolve database schema

#### `tests/` - Test Suite

- **Purpose**: Integration and unit tests
- **Organization**: Mirrors src/ structure for test organization
- **Types**: Unit tests, integration tests, API tests

## Project diagram

```node
Frontend (React)       Backend (Rust)         Blockchain (Ethereum)      Database (PostgreSQL)
  |                      |                        |                         |
  |--- Login (email) ---->| /login                |                         |
  |<-- JWT --------------| Generate JWT           |                         | Update users
  |                      |                        |                         |
  |--- Connect Wallet -->| /connect-wallet        |                         |
  | Sign Message         | Verify Signature       |                         | Store wallet_address
  |                      |                        |                         |
  |--- Link X ---------->| /auth/link/x (JWT)     |                         |
  | OAuth Flow          | Store social media     |                         | Update social_media_links
  |                      |                        |                         |
  |--- Mint NFT -------->|                        | Call mintSocialMediaNFT |
  | Sign Transaction    | /verify (check wallet) | Verify via AssetVerifier|
```
