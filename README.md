# NotifyMe - Notification Service API

NotifyMe is a comprehensive notification service API built with Go and clean architecture principles. It provides JWT authentication, Firebase push notifications, and email notifications with hot reload development support.

## Architecture

This project follows the hexagonal architecture (ports and adapters) pattern:

- **Domain Layer** (`internal/domain/`): Core business logic and entities
- **Application Layer** (`internal/application/`): Use cases and business rules
- **Infrastructure Layer** (`internal/infrastructure/`): External dependencies (database, JWT, config)
- **Adapter Layer** (`internal/adapter/`): HTTP handlers and middleware

## Features

### Authentication
- User registration and authentication
- JWT access tokens (15 minutes expiry)
- JWT refresh tokens (7 days expiry)
- Password hashing with bcrypt

### Notifications
- Firebase Cloud Messaging (FCM) for push notifications
- SMTP email notifications with TLS support
- Notification history and status tracking
- Bulk email sending capability
- Topic-based push notifications

### Infrastructure
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

### Notification Endpoints
- `POST /api/v1/notifications/push` - Send push notification (public)
- `POST /api/v1/notifications/email` - Send email notification (public)
- `POST /api/v1/notifications/` - Create notification (protected)
- `GET /api/v1/notifications/user/:user_id` - Get user notifications (protected)
- `GET /api/v1/notifications/:id` - Get notification by ID (protected)
- `PUT /api/v1/notifications/:id/read` - Mark notification as read (protected)

### Documentation
- `GET /swagger/index.html` - Interactive Swagger/OpenAPI documentation
- `GET /health` - Health check endpoint

## Setup

1. **Clone and setup:**
   ```bash
   git clone <repository-url>
   cd notifyMe
   cp .env.example .env
   ```

2. **Configure environment variables:**
   Edit the `.env` file with your database credentials, JWT secret, and notification settings.

   **Required for Firebase notifications:**
   - Set `FIREBASE_ENABLED=true`
   - Set `FIREBASE_CREDENTIALS_PATH` to your Firebase service account JSON file path
   
   **Required for email notifications:**
   - Set `EMAIL_ENABLED=true`
   - Configure SMTP settings (SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, FROM_EMAIL)

3. **Install dependencies:**
   ```bash
   go mod tidy
   ```

4. **Set up PostgreSQL:**
   Make sure PostgreSQL is running and create a database named `notifyme_db`.

5. **Run the application:**
   ```bash
   # Development with hot reload (recommended)
   air
   
   # Or run normally
   go run cmd/api/main.go
   ```

The server will start on `http://localhost:8080`.

6. **Access Swagger Documentation:**
   Visit `http://localhost:8080/swagger/index.html` to view the interactive API documentation.

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

## Notification Usage Examples

### Send push notification:
```bash
curl -X POST http://localhost:8080/api/v1/notifications/push \
  -H "Content-Type: application/json" \
  -d '{
    "token": "firebase-device-token",
    "title": "Test Notification",
    "message": "This is a test push notification",
    "data": {
      "key": "value"
    }
  }'
```

### Send email notification:
```bash
curl -X POST http://localhost:8080/api/v1/notifications/email \
  -H "Content-Type: application/json" \
  -d '{
    "to": "user@example.com",
    "subject": "Test Email",
    "body": "<h1>Hello!</h1><p>This is a test email.</p>"
  }'
```

### Create notification (requires authentication):
```bash
curl -X POST http://localhost:8080/api/v1/notifications/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-access-token>" \
  -d '{
    "user_id": "user-uuid",
    "type": "email",
    "title": "Welcome!",
    "message": "Welcome to our platform!"
  }'
```

### Get user notifications:
```bash
curl -X GET "http://localhost:8080/api/v1/notifications/user/user-uuid?limit=10&offset=0" \
  -H "Authorization: Bearer <your-access-token>"
```

## Swagger API Documentation

The application includes comprehensive Swagger/OpenAPI documentation that provides:

- **Interactive API Explorer**: Test all endpoints directly from the browser
- **Request/Response Schemas**: Complete data models for all API operations  
- **Authentication Support**: Built-in Bearer token authentication
- **Real-time Testing**: Execute API calls with live data

### Accessing Documentation

1. **Start the server**: `go run cmd/api/main.go`
2. **Open browser**: Navigate to `http://localhost:8080/swagger/index.html`
3. **Authenticate**: Use the "Authorize" button to add your Bearer token
4. **Explore**: Click on any endpoint to view details and test functionality

### Regenerating Documentation

When you modify API handlers or add new endpoints:

```bash
# Install swag CLI (first time only)
go install github.com/swaggo/swag/cmd/swag@latest

# Generate updated documentation
swag init -g cmd/api/main.go -o docs
```

## Hot Reload Development

This project includes Air for hot reloading during development:

### Installation
Air is automatically installed when you run `go mod tidy`. To install it globally:

```bash
go install github.com/air-verse/air@latest
```

### Usage
```bash
# Start development server with hot reload
air

# The server will automatically restart when you modify Go files
# Configuration is stored in .air.toml
```

### Hot Reload Features
- **Automatic Restart**: Server restarts on file changes
- **Fast Builds**: Incremental compilation for quick feedback
- **Excluded Files**: Test files and docs are ignored
- **Build Logs**: Compilation errors shown in terminal

## Project Structure

```
notifyMe/
├── cmd/
│   └── api/
│       └── main.go                 # Application entry point
├── internal/
│   ├── adapter/
│   │   └── http/
│   │       ├── handler/            # HTTP handlers (auth, notification)
│   │       ├── middleware/         # HTTP middleware
│   │       └── router.go          # Route definitions
│   ├── application/
│   │   └── usecase/               # Business use cases (auth, notification)
│   ├── domain/
│   │   ├── entity/                # Domain entities (user, notification)
│   │   └── repository/            # Repository interfaces
│   └── infrastructure/
│       ├── config/                # Configuration management
│       ├── database/              # Database implementations
│       ├── jwt/                   # JWT service implementation
│       └── notification/          # Firebase & email services
├── pkg/
│   └── logger/                    # Logging utilities
├── docs/                          # Generated Swagger documentation
│   ├── docs.go                   # Generated Go documentation
│   ├── swagger.json              # OpenAPI JSON specification  
│   └── swagger.yaml              # OpenAPI YAML specification
├── .air.toml                      # Air hot reload configuration
├── .env.example                   # Environment variables example
├── .env                          # Environment variables (created)
├── go.mod                         # Go module definition
└── README.md                      # This file
```

## Dependencies

### Core
- **Gin**: HTTP web framework
- **GORM**: ORM library with PostgreSQL driver
- **JWT**: JSON Web Token implementation
- **Bcrypt**: Password hashing
- **UUID**: UUID generation
- **Godotenv**: Environment variable loading

### Notifications
- **Firebase SDK**: Firebase Cloud Messaging for push notifications
- **Gomail**: SMTP email sending with TLS support
- **Google API**: Authentication and service options for Firebase

### Documentation
- **Swagger**: OpenAPI documentation generation and serving
- **Gin-Swagger**: Swagger middleware for Gin framework

### Development
- **Air**: Hot reload for Go applications during development

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

## Firebase Setup

1. **Create Firebase Project:**
   - Go to [Firebase Console](https://console.firebase.google.com/)
   - Create a new project or use existing one
   - Enable Cloud Messaging

2. **Generate Service Account:**
   - Go to Project Settings → Service Accounts
   - Click "Generate new private key"
   - Download the JSON file
   - Set `FIREBASE_CREDENTIALS_PATH` to the file path

3. **Client Integration:**
   - Add Firebase SDK to your mobile/web app
   - Get device tokens for push notifications
   - Use the `/notifications/push` endpoint to send notifications

## Email Setup

### Gmail Configuration:
1. Enable 2-factor authentication
2. Generate an App Password
3. Use App Password as `SMTP_PASSWORD`

### Other SMTP Providers:
- **Outlook**: smtp-mail.outlook.com:587
- **Yahoo**: smtp.mail.yahoo.com:587
- **Custom SMTP**: Configure your provider's settings

## Environment Variables

```bash
# Firebase Configuration
FIREBASE_ENABLED=true|false
FIREBASE_CREDENTIALS_PATH=/path/to/service-account.json

# Email Configuration  
EMAIL_ENABLED=true|false
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=your-email@gmail.com
FROM_NAME=NotifyMe
```