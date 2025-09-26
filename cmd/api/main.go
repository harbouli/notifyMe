package main

import (
	"fmt"
	"log"

	"hexagon-golang/internal/adapter/http"
	"hexagon-golang/internal/adapter/http/handler"
	"hexagon-golang/internal/adapter/http/middleware"
	"hexagon-golang/internal/application/usecase"
	"hexagon-golang/internal/infrastructure/config"
	"hexagon-golang/internal/infrastructure/database"
	"hexagon-golang/internal/infrastructure/jwt"
	"hexagon-golang/internal/infrastructure/notification"

	"github.com/gin-gonic/gin"

	_ "hexagon-golang/docs" // Import generated docs
)

// @title Hexagon Backend API
// @version 1.0
// @description A clean architecture backend service with JWT authentication, Firebase push notifications, and email notifications.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	gin.SetMode(cfg.Server.Mode)

	db, err := database.NewConnection(&database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		DBName:   cfg.Database.DBName,
		SSLMode:  cfg.Database.SSLMode,
	})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err := database.RunMigrations(db); err != nil {
		log.Fatal("Failed to run migrations:", err)
	}

	userRepo := database.NewUserRepository(db)
	refreshTokenRepo := database.NewRefreshTokenRepository(db)
	notificationRepo := database.NewNotificationRepository(db)

	jwtService := jwt.NewJWTService(
		cfg.JWT.SecretKey,
		cfg.JWT.AccessTokenExpiry,
		cfg.JWT.RefreshTokenExpiry,
	)

	var firebaseService *notification.FirebaseService
	if cfg.Notification.Firebase.Enabled {
		firebaseService, err = notification.NewFirebaseService(cfg.Notification.Firebase.CredentialsPath)
		if err != nil {
			log.Printf("Warning: Failed to initialize Firebase service: %v", err)
		}
	}

	var emailService *notification.EmailService
	if cfg.Notification.Email.Enabled {
		emailConfig := &notification.EmailConfig{
			SMTPHost:     cfg.Notification.Email.SMTPHost,
			SMTPPort:     cfg.Notification.Email.SMTPPort,
			SMTPUsername: cfg.Notification.Email.SMTPUsername,
			SMTPPassword: cfg.Notification.Email.SMTPPassword,
			FromEmail:    cfg.Notification.Email.FromEmail,
			FromName:     cfg.Notification.Email.FromName,
		}
		emailService = notification.NewEmailService(emailConfig)
	}

	authUseCase := usecase.NewAuthUseCase(userRepo, refreshTokenRepo, jwtService)
	notificationUseCase := usecase.NewNotificationUseCase(notificationRepo, userRepo, firebaseService, emailService)

	authHandler := handler.NewAuthHandler(authUseCase)
	notificationHandler := handler.NewNotificationHandler(notificationUseCase)
	authMiddleware := middleware.NewAuthMiddleware(jwtService)

	router := gin.Default()

	http.SetupRoutes(router, authHandler, notificationHandler, authMiddleware)

	serverAddr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Server starting on %s", serverAddr)

	if err := router.Run(serverAddr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}