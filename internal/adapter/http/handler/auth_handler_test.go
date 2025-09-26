package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"notifyMe/internal/application/usecase"
	"notifyMe/internal/domain/entity"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock AuthUseCase
type MockAuthUseCase struct {
	mock.Mock
}

func (m *MockAuthUseCase) Register(ctx context.Context, req *usecase.RegisterRequest) (*entity.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockAuthUseCase) Login(ctx context.Context, req *usecase.LoginRequest) (*usecase.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.LoginResponse), args.Error(1)
}

func (m *MockAuthUseCase) RefreshTokens(ctx context.Context, req *usecase.RefreshTokenRequest) (*usecase.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*usecase.LoginResponse), args.Error(1)
}

func (m *MockAuthUseCase) Logout(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthUseCase) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthUseCase) GetProfile(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

// Helper functions
func setupGin() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func createTestUser() *entity.User {
	return &entity.User{
		ID:        uuid.New(),
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
	}
}

func createLoginResponse(user *entity.User) *usecase.LoginResponse {
	return &usecase.LoginResponse{
		User:         user,
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-123",
	}
}

// Test Register endpoint
func TestAuthHandler_Register_Success(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	user := createTestUser()
	registerReq := usecase.RegisterRequest{
		Email:     "newuser@example.com",
		Username:  "newuser",
		Password:  "password123",
		FirstName: "Jane",
		LastName:  "Doe",
	}

	mockAuthUseCase.On("Register", mock.Anything, mock.MatchedBy(func(req *usecase.RegisterRequest) bool {
		return req.Email == registerReq.Email && req.Username == registerReq.Username
	})).Return(user, nil)

	router.POST("/register", handler.Register)

	reqBody, _ := json.Marshal(registerReq)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "User registered successfully", response["message"])
	assert.NotNil(t, response["user"])

	mockAuthUseCase.AssertExpectations(t)
}

func TestAuthHandler_Register_InvalidJSON(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	router.POST("/register", handler.Register)

	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "invalid character")
}

func TestAuthHandler_Register_EmailAlreadyExists(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	registerReq := usecase.RegisterRequest{
		Email:    "existing@example.com",
		Username: "newuser",
		Password: "password123",
	}

	mockAuthUseCase.On("Register", mock.Anything, mock.AnythingOfType("*usecase.RegisterRequest")).
		Return(nil, errors.New("email already exists"))

	router.POST("/register", handler.Register)

	reqBody, _ := json.Marshal(registerReq)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "email already exists", response["error"])

	mockAuthUseCase.AssertExpectations(t)
}

// Test Login endpoint
func TestAuthHandler_Login_Success(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	user := createTestUser()
	loginResp := createLoginResponse(user)
	loginReq := usecase.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockAuthUseCase.On("Login", mock.Anything, mock.MatchedBy(func(req *usecase.LoginRequest) bool {
		return req.Email == loginReq.Email && req.Password == loginReq.Password
	})).Return(loginResp, nil)

	router.POST("/login", handler.Login)

	reqBody, _ := json.Marshal(loginReq)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Login successful", response["message"])
	assert.NotNil(t, response["data"])

	mockAuthUseCase.AssertExpectations(t)
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	loginReq := usecase.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	mockAuthUseCase.On("Login", mock.Anything, mock.AnythingOfType("*usecase.LoginRequest")).
		Return(nil, errors.New("invalid credentials"))

	router.POST("/login", handler.Login)

	reqBody, _ := json.Marshal(loginReq)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid credentials", response["error"])

	mockAuthUseCase.AssertExpectations(t)
}

// Test RefreshToken endpoint
func TestAuthHandler_RefreshToken_Success(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	user := createTestUser()
	loginResp := createLoginResponse(user)
	refreshReq := usecase.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	mockAuthUseCase.On("RefreshTokens", mock.Anything, mock.MatchedBy(func(req *usecase.RefreshTokenRequest) bool {
		return req.RefreshToken == refreshReq.RefreshToken
	})).Return(loginResp, nil)

	router.POST("/refresh", handler.RefreshToken)

	reqBody, _ := json.Marshal(refreshReq)
	req, _ := http.NewRequest("POST", "/refresh", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Tokens refreshed successfully", response["message"])
	assert.NotNil(t, response["data"])

	mockAuthUseCase.AssertExpectations(t)
}

func TestAuthHandler_RefreshToken_InvalidToken(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	refreshReq := usecase.RefreshTokenRequest{
		RefreshToken: "invalid-token",
	}

	mockAuthUseCase.On("RefreshTokens", mock.Anything, mock.AnythingOfType("*usecase.RefreshTokenRequest")).
		Return(nil, errors.New("invalid refresh token"))

	router.POST("/refresh", handler.RefreshToken)

	reqBody, _ := json.Marshal(refreshReq)
	req, _ := http.NewRequest("POST", "/refresh", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid refresh token", response["error"])

	mockAuthUseCase.AssertExpectations(t)
}

// Test Logout endpoint
func TestAuthHandler_Logout_Success(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	userID := uuid.New()

	mockAuthUseCase.On("Logout", mock.Anything, userID).Return(nil)

	// Middleware to set userID in context
	router.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	})

	router.POST("/logout", handler.Logout)

	req, _ := http.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Logged out successfully", response["message"])

	mockAuthUseCase.AssertExpectations(t)
}

func TestAuthHandler_Logout_Unauthorized(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	router.POST("/logout", handler.Logout)

	req, _ := http.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Unauthorized", response["error"])
}

// Test LogoutAll endpoint
func TestAuthHandler_LogoutAll_Success(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	userID := uuid.New()

	mockAuthUseCase.On("LogoutAll", mock.Anything, userID).Return(nil)

	// Middleware to set userID in context
	router.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	})

	router.POST("/logout-all", handler.LogoutAll)

	req, _ := http.NewRequest("POST", "/logout-all", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Logged out from all devices successfully", response["message"])

	mockAuthUseCase.AssertExpectations(t)
}

// Test GetProfile endpoint
func TestAuthHandler_GetProfile_Success(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	userID := uuid.New()
	user := createTestUser()
	user.ID = userID

	mockAuthUseCase.On("GetProfile", mock.Anything, userID).Return(user, nil)

	// Middleware to set userID in context
	router.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	})

	router.GET("/profile", handler.GetProfile)

	req, _ := http.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Profile retrieved successfully", response["message"])
	assert.NotNil(t, response["user"])

	mockAuthUseCase.AssertExpectations(t)
}

func TestAuthHandler_GetProfile_UserNotFound(t *testing.T) {
	mockAuthUseCase := new(MockAuthUseCase)
	handler := NewAuthHandler(mockAuthUseCase)
	router := setupGin()

	userID := uuid.New()

	mockAuthUseCase.On("GetProfile", mock.Anything, userID).Return(nil, errors.New("user not found"))

	// Middleware to set userID in context
	router.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	})

	router.GET("/profile", handler.GetProfile)

	req, _ := http.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "user not found", response["error"])

	mockAuthUseCase.AssertExpectations(t)
}