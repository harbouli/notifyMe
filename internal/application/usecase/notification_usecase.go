package usecase

import (
	"context"
	"fmt"
	"time"

	"hexagon-golang/internal/domain/entity"
	"hexagon-golang/internal/domain/repository"
	"hexagon-golang/internal/infrastructure/notification"

	"github.com/google/uuid"
)

type NotificationUseCase struct {
	notificationRepo repository.NotificationRepository
	userRepo         repository.UserRepository
	firebaseService  *notification.FirebaseService
	emailService     *notification.EmailService
}

func NewNotificationUseCase(
	notificationRepo repository.NotificationRepository,
	userRepo repository.UserRepository,
	firebaseService *notification.FirebaseService,
	emailService *notification.EmailService,
) *NotificationUseCase {
	return &NotificationUseCase{
		notificationRepo: notificationRepo,
		userRepo:         userRepo,
		firebaseService:  firebaseService,
		emailService:     emailService,
	}
}

func (n *NotificationUseCase) CreateNotification(ctx context.Context, req *entity.NotificationRequest) (*entity.Notification, error) {
	user, err := n.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	notification := &entity.Notification{
		ID:      uuid.New(),
		UserID:  req.UserID,
		Type:    req.Type,
		Title:   req.Title,
		Message: req.Message,
		Data:    req.Data,
		Status:  entity.NotificationStatusPending,
	}

	if err := n.notificationRepo.Create(ctx, notification); err != nil {
		return nil, fmt.Errorf("failed to create notification: %w", err)
	}

	go func() {
		if err := n.sendNotification(context.Background(), notification, user); err != nil {
		}
	}()

	return notification, nil
}

func (n *NotificationUseCase) SendPushNotification(ctx context.Context, req *entity.PushNotificationRequest) error {
	if n.firebaseService == nil {
		return fmt.Errorf("Firebase service not configured")
	}

	err := n.firebaseService.SendNotification(ctx, req.Token, req.Title, req.Message, req.Data)
	if err != nil {
		return fmt.Errorf("failed to send push notification: %w", err)
	}

	return nil
}

func (n *NotificationUseCase) SendEmailNotification(ctx context.Context, req *entity.EmailNotificationRequest) error {
	if n.emailService == nil {
		return fmt.Errorf("email service not configured")
	}

	err := n.emailService.SendEmail(req.To, req.Subject, req.Body)
	if err != nil {
		return fmt.Errorf("failed to send email notification: %w", err)
	}

	return nil
}

func (n *NotificationUseCase) GetUserNotifications(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*entity.Notification, error) {
	notifications, err := n.notificationRepo.GetByUserID(ctx, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get user notifications: %w", err)
	}

	return notifications, nil
}

func (n *NotificationUseCase) GetNotificationByID(ctx context.Context, id uuid.UUID) (*entity.Notification, error) {
	notification, err := n.notificationRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get notification: %w", err)
	}

	return notification, nil
}

func (n *NotificationUseCase) MarkAsRead(ctx context.Context, id uuid.UUID) error {
	err := n.notificationRepo.UpdateStatus(ctx, id, entity.NotificationStatusSent)
	if err != nil {
		return fmt.Errorf("failed to mark notification as read: %w", err)
	}

	return nil
}

func (n *NotificationUseCase) ProcessPendingNotifications(ctx context.Context) error {
	notifications, err := n.notificationRepo.GetPendingNotifications(ctx, 100)
	if err != nil {
		return fmt.Errorf("failed to get pending notifications: %w", err)
	}

	for _, notification := range notifications {
		user, err := n.userRepo.GetByID(ctx, notification.UserID)
		if err != nil {
			continue
		}

		if err := n.sendNotification(ctx, notification, user); err != nil {
			continue
		}
	}

	return nil
}

func (n *NotificationUseCase) sendNotification(ctx context.Context, notification *entity.Notification, user *entity.User) error {
	var err error

	switch notification.Type {
	case entity.NotificationTypeEmail:
		if n.emailService != nil {
			err = n.emailService.SendEmail(user.Email, notification.Title, notification.Message)
		}
	case entity.NotificationTypePush:
		if n.firebaseService != nil && user.FCMToken != "" {
			err = n.firebaseService.SendNotification(ctx, user.FCMToken, notification.Title, notification.Message, notification.Data)
		}
	}

	now := time.Now()
	if err != nil {
		notification.Status = entity.NotificationStatusFailed
	} else {
		notification.Status = entity.NotificationStatusSent
		notification.SentAt = &now
	}

	n.notificationRepo.Update(ctx, notification)
	return err
}