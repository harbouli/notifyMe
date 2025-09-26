package handler

import (
	"context"
	"net/http"
	"crypto/rand"
	"encoding/base64"

	"notifyMe/internal/application/usecase"
	"notifyMe/internal/domain/entity"
	"notifyMe/internal/infrastructure/auth0"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthUseCaseInterface interface {
	Register(ctx context.Context, req *usecase.RegisterRequest) (*entity.User, error)
	Login(ctx context.Context, req *usecase.LoginRequest) (*usecase.LoginResponse, error)
	RefreshTokens(ctx context.Context, req *usecase.RefreshTokenRequest) (*usecase.LoginResponse, error)
	Logout(ctx context.Context, userID uuid.UUID) error
	LogoutAll(ctx context.Context, userID uuid.UUID) error
	GetProfile(ctx context.Context, userID uuid.UUID) (*entity.User, error)
}

type AuthHandler struct {
	authUseCase   AuthUseCaseInterface
	auth0Service  *auth0.Auth0Service
	jwtService    usecase.JWTService
}

func NewAuthHandler(authUseCase AuthUseCaseInterface, auth0Service *auth0.Auth0Service, jwtService usecase.JWTService) *AuthHandler {
	return &AuthHandler{
		authUseCase:  authUseCase,
		auth0Service: auth0Service,
		jwtService:   jwtService,
	}
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with email, username, and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body usecase.RegisterRequest true "User registration data"
// @Success 201 {object} map[string]interface{} "User registered successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req usecase.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.authUseCase.Register(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user":    user,
	})
}

// Login godoc
// @Summary User login
// @Description Authenticate user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body usecase.LoginRequest true "Login credentials"
// @Success 200 {object} map[string]interface{} "Login successful with tokens"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req usecase.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authUseCase.Login(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"data":    response,
	})
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Get new access and refresh tokens using refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body usecase.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} map[string]interface{} "Tokens refreshed successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req usecase.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authUseCase.RefreshTokens(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens refreshed successfully",
		"data":    response,
	})
}

// Logout godoc
// @Summary Logout user
// @Description Logout user from current session
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "Logged out successfully"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	err := h.authUseCase.Logout(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// LogoutAll godoc
// @Summary Logout from all devices
// @Description Logout user from all sessions/devices
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "Logged out from all devices successfully"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	err := h.authUseCase.LogoutAll(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out from all devices successfully"})
}

// GetProfile godoc
// @Summary Get user profile
// @Description Get current user profile information
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "Profile retrieved successfully"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/profile [get]
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := h.authUseCase.GetProfile(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile retrieved successfully",
		"user":    user,
	})
}

// Auth0Login godoc
// @Summary Initiate Auth0 Google OAuth login
// @Description Redirects to Auth0 for Google OAuth authentication
// @Tags Authentication
// @Produce json
// @Param redirect_uri query string false "Redirect URI after authentication"
// @Success 200 {object} map[string]interface{} "Authorization URL"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/auth0/login [get]
func (h *AuthHandler) Auth0Login(c *gin.Context) {
	if h.auth0Service == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Auth0 service not configured"})
		return
	}

	redirectURI := c.Query("redirect_uri")
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/api/v1/auth/auth0/callback"
	}

	// Generate a random state for CSRF protection
	state, err := generateRandomState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	// Store state in session/cookie (simplified for demo)
	c.SetCookie("auth0_state", state, 600, "/", "", false, true)

	authURL := h.auth0Service.GetAuthorizationURL(redirectURI, state)

	c.JSON(http.StatusOK, gin.H{
		"authorization_url": authURL,
		"state":             state,
	})
}

// Auth0Callback godoc
// @Summary Handle Auth0 OAuth callback
// @Description Handles the callback from Auth0 after user authentication
// @Tags Authentication
// @Produce json
// @Param code query string true "Authorization code from Auth0"
// @Param state query string true "State parameter for CSRF protection"
// @Success 200 {object} map[string]interface{} "Login successful"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /auth/auth0/callback [get]
func (h *AuthHandler) Auth0Callback(c *gin.Context) {
	if h.auth0Service == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Auth0 service not configured"})
		return
	}

	code := c.Query("code")
	state := c.Query("state")
	storedState, err := c.Cookie("auth0_state")

	if err != nil || state != storedState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code missing"})
		return
	}

	// Clear the state cookie
	c.SetCookie("auth0_state", "", -1, "/", "", false, true)

	redirectURI := "http://localhost:8080/api/v1/auth/auth0/callback"

	// Exchange code for token
	tokenResp, err := h.auth0Service.ExchangeCodeForToken(code, redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to exchange code for token"})
		return
	}

	// Validate the token and get user info
	auth0User, err := h.auth0Service.ValidateAuth0Token(tokenResp.AccessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// This is a simplified approach - in a real app you'd want to inject the user repository
	// For now, we'll create a mock or modify this to work with your existing architecture
	c.JSON(http.StatusOK, gin.H{
		"message":    "Auth0 authentication successful",
		"user":       auth0User,
		"token":      tokenResp.AccessToken,
		"token_type": tokenResp.TokenType,
		"expires_in": tokenResp.ExpiresIn,
	})
}

// generateRandomState generates a random state string for CSRF protection
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}