# Hexagon Backend - Go Authentication Service

A clean architecture backend service built with Go, implementing JWT authentication with access and refresh tokens using hexagonal architecture patterns.

## Architecture

This project follows the hexagonal architecture (ports and adapters) pattern:

- **Domain Layer** (`internal/domain/`): Core business logic and entities
- **Application Layer** (`internal/application/`): Use cases and business rules
- **Infrastructure Layer** (`internal/infrastructure/`): External dependencies (database, JWT, config)
- **Adapter Layer** (`internal/adapter/`): HTTP handlers and middleware

## Features

- User registration and authentication
- JWT access tokens (15 minutes expiry)
- JWT refresh tokens (7 days expiry)
- Password hashing with bcrypt
- GORM ORM with PostgreSQL
- Clean hexagonal architecture
- CORS middleware
- Environment-based configuration

## API Endpoints

### Public Endpoints
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /health` - Health check

### Protected Endpoints
- `POST /api/v1/auth/logout` - Logout current session
- `POST /api/v1/auth/logout-all` - Logout all sessions
- `GET /api/v1/auth/profile` - Get user profile
- `GET /api/v1/protected` - Example protected route

## Setup

1. **Clone and setup:**
   ```bash
   git clone <repository-url>
   cd hexagon-golang
   cp .env.example .env
   ```

2. **Configure environment variables:**
   Edit the `.env` file with your database credentials and JWT secret.

3. **Install dependencies:**
   ```bash
   go mod tidy
   ```

4. **Set up PostgreSQL:**
   Make sure PostgreSQL is running and create a database named `hexagon_db`.

5. **Run the application:**
   ```bash
   go run cmd/api/main.go
   ```

The server will start on `http://localhost:8080`.

## API Usage Examples

### Register a new user:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Login:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

### Access protected endpoint:
```bash
curl -X GET http://localhost:8080/api/v1/auth/profile \
  -H "Authorization: Bearer <your-access-token>"
```

### Refresh tokens:
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<your-refresh-token>"
  }'
```

## Project Structure

```
hexagon-golang/
├── cmd/
│   └── api/
│       └── main.go                 # Application entry point
├── internal/
│   ├── adapter/
│   │   └── http/
│   │       ├── handler/            # HTTP handlers
│   │       ├── middleware/         # HTTP middleware
│   │       └── router.go          # Route definitions
│   ├── application/
│   │   └── usecase/               # Business use cases
│   ├── domain/
│   │   ├── entity/                # Domain entities
│   │   └── repository/            # Repository interfaces
│   └── infrastructure/
│       ├── config/                # Configuration management
│       ├── database/              # Database implementations
│       └── jwt/                   # JWT service implementation
├── pkg/
│   └── logger/                    # Logging utilities
├── .env.example                   # Environment variables example
├── go.mod                         # Go module definition
└── README.md                      # This file
```

## Dependencies

- **Gin**: HTTP web framework
- **GORM**: ORM library with PostgreSQL driver
- **JWT**: JSON Web Token implementation
- **Bcrypt**: Password hashing
- **UUID**: UUID generation
- **Godotenv**: Environment variable loading

## Security Features

- Password hashing with bcrypt
- JWT tokens with configurable expiry
- Refresh token rotation
- Token revocation support
- CORS middleware
- Input validation

## Development

To extend this backend:

1. Add new entities in `internal/domain/entity/`
2. Define repository interfaces in `internal/domain/repository/`
3. Implement use cases in `internal/application/usecase/`
4. Create repository implementations in `internal/infrastructure/database/`
5. Add HTTP handlers in `internal/adapter/http/handler/`
6. Update routes in `internal/adapter/http/router.go`