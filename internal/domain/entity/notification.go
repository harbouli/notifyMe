package entity

import (
	"time"

	"github.com/google/uuid"
)

type NotificationType string

const (
	NotificationTypeEmail NotificationType = "email"
	NotificationTypePush  NotificationType = "push"
)

type NotificationStatus string

const (
	NotificationStatusPending NotificationStatus = "pending"
	NotificationStatusSent    NotificationStatus = "sent"
	NotificationStatusFailed  NotificationStatus = "failed"
)

type Notification struct {
	ID        uuid.UUID          `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID          `json:"user_id" gorm:"type:uuid;not null;index"`
	Type      NotificationType   `json:"type" gorm:"type:varchar(20);not null"`
	Title     string             `json:"title" gorm:"type:varchar(255);not null"`
	Message   string             `json:"message" gorm:"type:text;not null"`
	Data      map[string]string  `json:"data" gorm:"type:jsonb"`
	Status    NotificationStatus `json:"status" gorm:"type:varchar(20);default:'pending'"`
	CreatedAt time.Time          `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time          `json:"updated_at" gorm:"autoUpdateTime"`
	SentAt    *time.Time         `json:"sent_at"`

	User User `json:"user" gorm:"foreignKey:UserID"`
}

type NotificationRequest struct {
	UserID  uuid.UUID         `json:"user_id" binding:"required"`
	Type    NotificationType  `json:"type" binding:"required,oneof=email push"`
	Title   string            `json:"title" binding:"required"`
	Message string            `json:"message" binding:"required"`
	Data    map[string]string `json:"data"`
}

type PushNotificationRequest struct {
	Token   string            `json:"token" binding:"required"`
	Title   string            `json:"title" binding:"required"`
	Message string            `json:"message" binding:"required"`
	Data    map[string]string `json:"data"`
}

type EmailNotificationRequest struct {
	To      string            `json:"to" binding:"required,email"`
	Subject string            `json:"subject" binding:"required"`
	Body    string            `json:"body" binding:"required"`
	Data    map[string]string `json:"data"`
}