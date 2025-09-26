package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"notifyMe/internal/domain/entity"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// Mock repositories
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type MockRefreshTokenRepository struct {
	mock.Mock
}

func (m *MockRefreshTokenRepository) Create(ctx context.Context, token *entity.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) GetByToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*entity.RefreshToken, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*entity.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) Update(ctx context.Context, token *entity.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateTokens(userID uuid.UUID) (accessToken, refreshToken string, err error) {
	args := m.Called(userID)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockJWTService) ValidateAccessToken(token string) (*Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Claims), args.Error(1)
}

func (m *MockJWTService) ValidateRefreshToken(token string) (*Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Claims), args.Error(1)
}

// Test fixtures
func createTestUser() *entity.User {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	return &entity.User{
		ID:           uuid.New(),
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: string(hashedPassword),
		FirstName:    "John",
		LastName:     "Doe",
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func createTestRefreshToken(userID uuid.UUID) *entity.RefreshToken {
	return &entity.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     "refresh-token-123",
		ExpiresAt: time.Now().Add(24 * 7 * time.Hour),
		IsRevoked: false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Test cases for Register
func TestAuthUseCase_Register_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &RegisterRequest{
		Email:     "newuser@example.com",
		Username:  "newuser",
		Password:  "password123",
		FirstName: "Jane",
		LastName:  "Doe",
	}

	// Mock expectations
	mockUserRepo.On("GetByEmail", mock.Anything, req.Email).Return(nil, errors.New("not found"))
	mockUserRepo.On("GetByUsername", mock.Anything, req.Username).Return(nil, errors.New("not found"))
	mockUserRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)

	// Execute
	result, err := authUseCase.Register(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, req.Email, result.Email)
	assert.Equal(t, req.Username, result.Username)
	assert.Equal(t, req.FirstName, result.FirstName)
	assert.Equal(t, req.LastName, result.LastName)
	assert.True(t, result.IsActive)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthUseCase_Register_EmailAlreadyExists(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &RegisterRequest{
		Email:    "existing@example.com",
		Username: "newuser",
		Password: "password123",
	}

	existingUser := createTestUser()
	mockUserRepo.On("GetByEmail", mock.Anything, req.Email).Return(existingUser, nil)

	// Execute
	result, err := authUseCase.Register(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "email already exists", err.Error())
	mockUserRepo.AssertExpectations(t)
}

func TestAuthUseCase_Register_UsernameAlreadyExists(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &RegisterRequest{
		Email:    "newuser@example.com",
		Username: "existinguser",
		Password: "password123",
	}

	existingUser := createTestUser()
	mockUserRepo.On("GetByEmail", mock.Anything, req.Email).Return(nil, errors.New("not found"))
	mockUserRepo.On("GetByUsername", mock.Anything, req.Username).Return(existingUser, nil)

	// Execute
	result, err := authUseCase.Register(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "username already exists", err.Error())
	mockUserRepo.AssertExpectations(t)
}

// Test cases for Login
func TestAuthUseCase_Login_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	user := createTestUser()
	user.Email = req.Email

	// Mock expectations
	mockUserRepo.On("GetByEmail", mock.Anything, req.Email).Return(user, nil)
	mockJWTService.On("GenerateTokens", user.ID).Return("access-token", "refresh-token", nil)
	mockRefreshTokenRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).Return(nil)

	// Execute
	result, err := authUseCase.Login(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, user, result.User)
	assert.Equal(t, "access-token", result.AccessToken)
	assert.Equal(t, "refresh-token", result.RefreshToken)
	mockUserRepo.AssertExpectations(t)
	mockJWTService.AssertExpectations(t)
	mockRefreshTokenRepo.AssertExpectations(t)
}

func TestAuthUseCase_Login_UserNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "password123",
	}

	mockUserRepo.On("GetByEmail", mock.Anything, req.Email).Return(nil, errors.New("not found"))

	// Execute
	result, err := authUseCase.Login(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "invalid credentials", err.Error())
	mockUserRepo.AssertExpectations(t)
}

func TestAuthUseCase_Login_InvalidPassword(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	user := createTestUser()
	user.Email = req.Email

	mockUserRepo.On("GetByEmail", mock.Anything, req.Email).Return(user, nil)

	// Execute
	result, err := authUseCase.Login(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "invalid credentials", err.Error())
	mockUserRepo.AssertExpectations(t)
}

func TestAuthUseCase_Login_DeactivatedAccount(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	user := createTestUser()
	user.Email = req.Email
	user.IsActive = false

	mockUserRepo.On("GetByEmail", mock.Anything, req.Email).Return(user, nil)

	// Execute
	result, err := authUseCase.Login(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "account is deactivated", err.Error())
	mockUserRepo.AssertExpectations(t)
}

// Test cases for RefreshTokens
func TestAuthUseCase_RefreshTokens_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	userID := uuid.New()
	req := &RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	user := createTestUser()
	user.ID = userID
	refreshToken := createTestRefreshToken(userID)
	refreshToken.Token = req.RefreshToken

	claims := &Claims{
		UserID: userID,
		Type:   "refresh",
	}

	// Mock expectations
	mockJWTService.On("ValidateRefreshToken", req.RefreshToken).Return(claims, nil)
	mockRefreshTokenRepo.On("GetByToken", mock.Anything, req.RefreshToken).Return(refreshToken, nil)
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockRefreshTokenRepo.On("Update", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).Return(nil)
	mockJWTService.On("GenerateTokens", userID).Return("new-access-token", "new-refresh-token", nil)
	mockRefreshTokenRepo.On("Create", mock.Anything, mock.AnythingOfType("*entity.RefreshToken")).Return(nil)

	// Execute
	result, err := authUseCase.RefreshTokens(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, user, result.User)
	assert.Equal(t, "new-access-token", result.AccessToken)
	assert.Equal(t, "new-refresh-token", result.RefreshToken)
	mockJWTService.AssertExpectations(t)
	mockRefreshTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthUseCase_RefreshTokens_InvalidToken(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	req := &RefreshTokenRequest{
		RefreshToken: "invalid-token",
	}

	mockJWTService.On("ValidateRefreshToken", req.RefreshToken).Return(nil, errors.New("invalid token"))

	// Execute
	result, err := authUseCase.RefreshTokens(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "invalid refresh token", err.Error())
	mockJWTService.AssertExpectations(t)
}

func TestAuthUseCase_RefreshTokens_RevokedToken(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	userID := uuid.New()
	req := &RefreshTokenRequest{
		RefreshToken: "revoked-token",
	}

	refreshToken := createTestRefreshToken(userID)
	refreshToken.Token = req.RefreshToken
	refreshToken.IsRevoked = true

	claims := &Claims{
		UserID: userID,
		Type:   "refresh",
	}

	mockJWTService.On("ValidateRefreshToken", req.RefreshToken).Return(claims, nil)
	mockRefreshTokenRepo.On("GetByToken", mock.Anything, req.RefreshToken).Return(refreshToken, nil)

	// Execute
	result, err := authUseCase.RefreshTokens(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "refresh token is revoked", err.Error())
	mockJWTService.AssertExpectations(t)
	mockRefreshTokenRepo.AssertExpectations(t)
}

// Test cases for Logout
func TestAuthUseCase_Logout_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	userID := uuid.New()

	mockRefreshTokenRepo.On("RevokeByUserID", mock.Anything, userID).Return(nil)

	// Execute
	err := authUseCase.Logout(context.Background(), userID)

	// Assert
	assert.NoError(t, err)
	mockRefreshTokenRepo.AssertExpectations(t)
}

// Test cases for GetProfile
func TestAuthUseCase_GetProfile_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	userID := uuid.New()
	user := createTestUser()
	user.ID = userID

	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	// Execute
	result, err := authUseCase.GetProfile(context.Background(), userID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, user, result)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthUseCase_GetProfile_UserNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRefreshTokenRepo := new(MockRefreshTokenRepository)
	mockJWTService := new(MockJWTService)

	authUseCase := NewAuthUseCase(mockUserRepo, mockRefreshTokenRepo, mockJWTService)

	userID := uuid.New()

	mockUserRepo.On("GetByID", mock.Anything, userID).Return(nil, errors.New("user not found"))

	// Execute
	result, err := authUseCase.GetProfile(context.Background(), userID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "user not found", err.Error())
	mockUserRepo.AssertExpectations(t)
}