package database

import (
	"context"

	"notifyMe/internal/domain/entity"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type refreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) *refreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

func (r *refreshTokenRepository) Create(ctx context.Context, token *entity.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *refreshTokenRepository) GetByToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	var refreshToken entity.RefreshToken
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&refreshToken).Error
	if err != nil {
		return nil, err
	}
	return &refreshToken, nil
}

func (r *refreshTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*entity.RefreshToken, error) {
	var tokens []*entity.RefreshToken
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&tokens).Error
	return tokens, err
}

func (r *refreshTokenRepository) Update(ctx context.Context, token *entity.RefreshToken) error {
	return r.db.WithContext(ctx).Save(token).Error
}

func (r *refreshTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&entity.RefreshToken{}).Error
}

func (r *refreshTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&entity.RefreshToken{}).Error
}

func (r *refreshTokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&entity.RefreshToken{}).
		Where("user_id = ? AND is_revoked = ?", userID, false).
		Update("is_revoked", true).Error
}