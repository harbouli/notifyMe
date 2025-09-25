package http

import (
	"hexagon-golang/internal/adapter/http/handler"
	"hexagon-golang/internal/adapter/http/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(
	router *gin.Engine,
	authHandler *handler.AuthHandler,
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
			
			authorized := auth.Group("/")
			authorized.Use(authMiddleware.RequireAuth())
			{
				authorized.POST("/logout", authHandler.Logout)
				authorized.POST("/logout-all", authHandler.LogoutAll)
				authorized.GET("/profile", authHandler.GetProfile)
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

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "OK",
			"message": "Server is running",
		})
	})
}