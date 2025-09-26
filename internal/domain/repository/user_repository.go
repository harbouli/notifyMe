package repository

import (
	"context"

	"notifyMe/internal/domain/entity"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.User, error)
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
	GetByUsername(ctx context.Context, username string) (*entity.User, error)
	GetByExternalID(ctx context.Context, externalID string) (*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *entity.RefreshToken) error
	GetByToken(ctx context.Context, token string) (*entity.RefreshToken, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*entity.RefreshToken, error)
	Update(ctx context.Context, token *entity.RefreshToken) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	RevokeByUserID(ctx context.Context, userID uuid.UUID) error
}

type NotificationRepository interface {
	Create(ctx context.Context, notification *entity.Notification) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Notification, error)
	GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*entity.Notification, error)
	Update(ctx context.Context, notification *entity.Notification) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status entity.NotificationStatus) error
	GetPendingNotifications(ctx context.Context, limit int) ([]*entity.Notification, error)
}