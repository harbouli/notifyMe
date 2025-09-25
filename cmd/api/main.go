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

	"github.com/gin-gonic/gin"
)

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

	jwtService := jwt.NewJWTService(
		cfg.JWT.SecretKey,
		cfg.JWT.AccessTokenExpiry,
		cfg.JWT.RefreshTokenExpiry,
	)

	authUseCase := usecase.NewAuthUseCase(userRepo, refreshTokenRepo, jwtService)

	authHandler := handler.NewAuthHandler(authUseCase)
	authMiddleware := middleware.NewAuthMiddleware(jwtService)

	router := gin.Default()

	http.SetupRoutes(router, authHandler, authMiddleware)

	serverAddr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Server starting on %s", serverAddr)

	if err := router.Run(serverAddr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}