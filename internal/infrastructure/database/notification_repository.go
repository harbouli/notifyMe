package database

import (
	"context"

	"hexagon-golang/internal/domain/entity"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type notificationRepository struct {
	db *gorm.DB
}

func NewNotificationRepository(db *gorm.DB) *notificationRepository {
	return &notificationRepository{
		db: db,
	}
}

func (r *notificationRepository) Create(ctx context.Context, notification *entity.Notification) error {
	return r.db.WithContext(ctx).Create(notification).Error
}

func (r *notificationRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.Notification, error) {
	var notification entity.Notification
	err := r.db.WithContext(ctx).Preload("User").First(&notification, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &notification, nil
}

func (r *notificationRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*entity.Notification, error) {
	var notifications []*entity.Notification
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&notifications).Error
	return notifications, err
}

func (r *notificationRepository) Update(ctx context.Context, notification *entity.Notification) error {
	return r.db.WithContext(ctx).Save(notification).Error
}

func (r *notificationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&entity.Notification{}, "id = ?", id).Error
}

func (r *notificationRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status entity.NotificationStatus) error {
	return r.db.WithContext(ctx).Model(&entity.Notification{}).
		Where("id = ?", id).
		Update("status", status).Error
}

func (r *notificationRepository) GetPendingNotifications(ctx context.Context, limit int) ([]*entity.Notification, error) {
	var notifications []*entity.Notification
	err := r.db.WithContext(ctx).
		Preload("User").
		Where("status = ?", entity.NotificationStatusPending).
		Order("created_at ASC").
		Limit(limit).
		Find(&notifications).Error
	return notifications, err
}