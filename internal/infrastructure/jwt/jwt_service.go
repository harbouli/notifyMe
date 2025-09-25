package jwt

import (
	"errors"
	"time"

	"hexagon-golang/internal/application/usecase"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type jwtService struct {
	secretKey     []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

type JWTClaims struct {
	UserID uuid.UUID `json:"user_id"`
	Type   string    `json:"type"`
	jwt.RegisteredClaims
}

const (
	AccessTokenType  = "access"
	RefreshTokenType = "refresh"
)

func NewJWTService(secretKey string, accessExpiry, refreshExpiry time.Duration) *jwtService {
	return &jwtService{
		secretKey:     []byte(secretKey),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

func (s *jwtService) GenerateTokens(userID uuid.UUID) (accessToken, refreshToken string, err error) {
	accessToken, err = s.generateToken(userID, AccessTokenType, s.accessExpiry)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.generateToken(userID, RefreshTokenType, s.refreshExpiry)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *jwtService) generateToken(userID uuid.UUID, tokenType string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID: userID,
		Type:   tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "hexagon-backend",
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secretKey)
}

func (s *jwtService) ValidateAccessToken(tokenString string) (*usecase.Claims, error) {
	return s.validateToken(tokenString, AccessTokenType)
}

func (s *jwtService) ValidateRefreshToken(tokenString string) (*usecase.Claims, error) {
	return s.validateToken(tokenString, RefreshTokenType)
}

func (s *jwtService) validateToken(tokenString, expectedType string) (*usecase.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.Type != expectedType {
		return nil, errors.New("invalid token type")
	}

	return &usecase.Claims{
		UserID: claims.UserID,
		Type:   claims.Type,
	}, nil
}