package http

import (
	"notifyMe/internal/adapter/http/handler"
	"notifyMe/internal/adapter/http/middleware"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRoutes(
	router *gin.Engine,
	authHandler *handler.AuthHandler,
	notificationHandler *handler.NotificationHandler,
	authMiddleware *middleware.AuthMiddleware,
) {
	router.Use(authMiddleware.CORS())

	api := router.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
			
			// Auth0 OAuth routes
			auth.GET("/auth0/login", authHandler.Auth0Login)
			auth.GET("/auth0/callback", authHandler.Auth0Callback)
			
			authorized := auth.Group("/")
			authorized.Use(authMiddleware.RequireAuth())
			{
				authorized.POST("/logout", authHandler.Logout)
				authorized.POST("/logout-all", authHandler.LogoutAll)
				authorized.GET("/profile", authHandler.GetProfile)
			}
		}

		notifications := api.Group("/notifications")
		{
			notifications.POST("/push", notificationHandler.SendPushNotification)
			notifications.POST("/email", notificationHandler.SendEmailNotification)
			
			authorized := notifications.Group("/")
			authorized.Use(authMiddleware.RequireAuth())
			{
				authorized.POST("/", notificationHandler.CreateNotification)
				authorized.GET("/user/:user_id", notificationHandler.GetUserNotifications)
				authorized.GET("/:id", notificationHandler.GetNotificationByID)
				authorized.PUT("/:id/read", notificationHandler.MarkAsRead)
			}
		}

		protected := api.Group("/")
		protected.Use(authMiddleware.RequireAuth())
		{
			protected.GET("/protected", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "This is a protected route",
					"user_id": c.GetString("userID"),
				})
			})
		}
	}

	// Health check endpoint
	// @Summary Health check
	// @Description Check if the server is running
	// @Tags System
	// @Produce json
	// @Success 200 {object} map[string]interface{} "Server is running"
	// @Router /health [get]
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "OK",
			"message": "Server is running",
		})
	})

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}