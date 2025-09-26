package jwt

import (
	"testing"
	"time"

	"notifyMe/internal/application/usecase"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewJWTService(t *testing.T) {
	secretKey := "test-secret-key"
	accessExpiry := 15 * time.Minute
	refreshExpiry := 7 * 24 * time.Hour

	service := NewJWTService(secretKey, accessExpiry, refreshExpiry)

	assert.NotNil(t, service)
	assert.Equal(t, []byte(secretKey), service.secretKey)
	assert.Equal(t, accessExpiry, service.accessExpiry)
	assert.Equal(t, refreshExpiry, service.refreshExpiry)
}

func TestJWTService_GenerateTokens_Success(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	accessToken, refreshToken, err := service.GenerateTokens(userID)

	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
	assert.NotEqual(t, accessToken, refreshToken)

	// Verify access token claims
	accessClaims, err := service.ValidateAccessToken(accessToken)
	assert.NoError(t, err)
	assert.IsType(t, &usecase.Claims{}, accessClaims)
	assert.Equal(t, userID, accessClaims.UserID)
	assert.Equal(t, AccessTokenType, accessClaims.Type)

	// Verify refresh token claims
	refreshClaims, err := service.ValidateRefreshToken(refreshToken)
	assert.NoError(t, err)
	assert.IsType(t, &usecase.Claims{}, refreshClaims)
	assert.Equal(t, userID, refreshClaims.UserID)
	assert.Equal(t, RefreshTokenType, refreshClaims.Type)
}

func TestJWTService_GenerateToken_Success(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	token, err := service.generateToken(userID, AccessTokenType, 15*time.Minute)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse and verify token
	parsedToken, err := jwt.ParseWithClaims(token, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return service.secretKey, nil
	})

	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(*JWTClaims)
	assert.True(t, ok)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, AccessTokenType, claims.Type)
	assert.Equal(t, "notifyme-backend", claims.Issuer)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.True(t, claims.ExpiresAt.After(time.Now()))
}

func TestJWTService_ValidateAccessToken_Success(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	accessToken, _, err := service.GenerateTokens(userID)
	assert.NoError(t, err)

	claims, err := service.ValidateAccessToken(accessToken)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.IsType(t, &usecase.Claims{}, claims)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, AccessTokenType, claims.Type)
}

func TestJWTService_ValidateAccessToken_InvalidToken(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)

	claims, err := service.ValidateAccessToken("invalid-token")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateAccessToken_WrongTokenType(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	_, refreshToken, err := service.GenerateTokens(userID)
	assert.NoError(t, err)

	// Try to validate refresh token as access token
	claims, err := service.ValidateAccessToken(refreshToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestJWTService_ValidateAccessToken_WrongSecretKey(t *testing.T) {
	service1 := NewJWTService("secret-1", 15*time.Minute, 7*24*time.Hour)
	service2 := NewJWTService("secret-2", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	accessToken, _, err := service1.GenerateTokens(userID)
	assert.NoError(t, err)

	// Try to validate with different secret
	claims, err := service2.ValidateAccessToken(accessToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateRefreshToken_Success(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	_, refreshToken, err := service.GenerateTokens(userID)
	assert.NoError(t, err)

	claims, err := service.ValidateRefreshToken(refreshToken)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.IsType(t, &usecase.Claims{}, claims)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, RefreshTokenType, claims.Type)
}

func TestJWTService_ValidateRefreshToken_InvalidToken(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)

	claims, err := service.ValidateRefreshToken("invalid-token")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateRefreshToken_WrongTokenType(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	accessToken, _, err := service.GenerateTokens(userID)
	assert.NoError(t, err)

	// Try to validate access token as refresh token
	claims, err := service.ValidateRefreshToken(accessToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestJWTService_ValidateToken_ExpiredToken(t *testing.T) {
	service := NewJWTService("test-secret", -1*time.Hour, 7*24*time.Hour) // Negative expiry for immediate expiration
	userID := uuid.New()

	accessToken, _, err := service.GenerateTokens(userID)
	assert.NoError(t, err)

	// Wait a moment to ensure expiration
	time.Sleep(10 * time.Millisecond)

	claims, err := service.ValidateAccessToken(accessToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTService_ValidateToken_UnexpectedSigningMethod(t *testing.T) {
	service := NewJWTService("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()

	// Create a token with RS256 instead of HS256
	claims := JWTClaims{
		UserID: userID,
		Type:   AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "notifyme-backend",
			Subject:   userID.String(),
		},
	}

	// This will create a malformed token for our service
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString([]byte("fake-key"))

	result, err := service.ValidateAccessToken(tokenString)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestJWTClaims_Structure(t *testing.T) {
	userID := uuid.New()
	claims := JWTClaims{
		UserID: userID,
		Type:   AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "test-issuer",
			Subject: userID.String(),
		},
	}

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, AccessTokenType, claims.Type)
	assert.Equal(t, "test-issuer", claims.Issuer)
	assert.Equal(t, userID.String(), claims.Subject)
}

func TestTokenTypeConstants(t *testing.T) {
	assert.Equal(t, "access", AccessTokenType)
	assert.Equal(t, "refresh", RefreshTokenType)
}