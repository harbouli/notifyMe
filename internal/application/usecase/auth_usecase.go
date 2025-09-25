package usecase

import (
	"context"
	"errors"
	"time"

	"hexagon-golang/internal/domain/entity"
	"hexagon-golang/internal/domain/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthUseCase struct {
	userRepo         repository.UserRepository
	refreshTokenRepo repository.RefreshTokenRepository
	jwtService       JWTService
}

type JWTService interface {
	GenerateTokens(userID uuid.UUID) (accessToken, refreshToken string, err error)
	ValidateAccessToken(token string) (*Claims, error)
	ValidateRefreshToken(token string) (*Claims, error)
}

type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	Type   string    `json:"type"`
}

type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required,min=3,max=50"`
	Password  string `json:"password" binding:"required,min=6"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	User         *entity.User `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func NewAuthUseCase(
	userRepo repository.UserRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	jwtService JWTService,
) *AuthUseCase {
	return &AuthUseCase{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		jwtService:       jwtService,
	}
}

func (uc *AuthUseCase) Register(ctx context.Context, req *RegisterRequest) (*entity.User, error) {
	existingUser, _ := uc.userRepo.GetByEmail(ctx, req.Email)
	if existingUser != nil {
		return nil, errors.New("email already exists")
	}

	existingUser, _ = uc.userRepo.GetByUsername(ctx, req.Username)
	if existingUser != nil {
		return nil, errors.New("username already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	user := &entity.User{
		ID:           uuid.New(),
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, errors.New("failed to create user")
	}

	return user, nil
}

func (uc *AuthUseCase) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	user, err := uc.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	accessToken, refreshToken, err := uc.jwtService.GenerateTokens(user.ID)
	if err != nil {
		return nil, errors.New("failed to generate tokens")
	}

	refreshTokenEntity := &entity.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(24 * 7 * time.Hour),
		IsRevoked: false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.refreshTokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		return nil, errors.New("failed to save refresh token")
	}

	return &LoginResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (uc *AuthUseCase) RefreshTokens(ctx context.Context, req *RefreshTokenRequest) (*LoginResponse, error) {
	claims, err := uc.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	refreshTokenEntity, err := uc.refreshTokenRepo.GetByToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, errors.New("refresh token not found")
	}

	if refreshTokenEntity.IsRevoked {
		return nil, errors.New("refresh token is revoked")
	}

	if time.Now().After(refreshTokenEntity.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	user, err := uc.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	refreshTokenEntity.IsRevoked = true
	refreshTokenEntity.UpdatedAt = time.Now()
	if err := uc.refreshTokenRepo.Update(ctx, refreshTokenEntity); err != nil {
		return nil, errors.New("failed to revoke old refresh token")
	}

	accessToken, newRefreshToken, err := uc.jwtService.GenerateTokens(user.ID)
	if err != nil {
		return nil, errors.New("failed to generate new tokens")
	}

	newRefreshTokenEntity := &entity.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(24 * 7 * time.Hour),
		IsRevoked: false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := uc.refreshTokenRepo.Create(ctx, newRefreshTokenEntity); err != nil {
		return nil, errors.New("failed to save new refresh token")
	}

	return &LoginResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (uc *AuthUseCase) Logout(ctx context.Context, userID uuid.UUID) error {
	return uc.refreshTokenRepo.RevokeByUserID(ctx, userID)
}

func (uc *AuthUseCase) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	return uc.refreshTokenRepo.RevokeByUserID(ctx, userID)
}

func (uc *AuthUseCase) GetProfile(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	return uc.userRepo.GetByID(ctx, userID)
}