package handler

import (
	"net/http"
	"strconv"

	"hexagon-golang/internal/application/usecase"
	"hexagon-golang/internal/domain/entity"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type NotificationHandler struct {
	notificationUseCase *usecase.NotificationUseCase
}

func NewNotificationHandler(notificationUseCase *usecase.NotificationUseCase) *NotificationHandler {
	return &NotificationHandler{
		notificationUseCase: notificationUseCase,
	}
}

// CreateNotification godoc
// @Summary Create a notification
// @Description Create a new notification for a user
// @Tags Notifications
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body entity.NotificationRequest true "Notification data"
// @Success 201 {object} map[string]interface{} "Notification created successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/ [post]
func (h *NotificationHandler) CreateNotification(c *gin.Context) {
	var req entity.NotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	notification, err := h.notificationUseCase.CreateNotification(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"notification": notification})
}

// SendPushNotification godoc
// @Summary Send push notification
// @Description Send a push notification via Firebase Cloud Messaging
// @Tags Notifications
// @Accept json
// @Produce json
// @Param request body entity.PushNotificationRequest true "Push notification data"
// @Success 200 {object} map[string]interface{} "Push notification sent successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/push [post]
func (h *NotificationHandler) SendPushNotification(c *gin.Context) {
	var req entity.PushNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.notificationUseCase.SendPushNotification(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Push notification sent successfully"})
}

// SendEmailNotification godoc
// @Summary Send email notification
// @Description Send an email notification via SMTP
// @Tags Notifications
// @Accept json
// @Produce json
// @Param request body entity.EmailNotificationRequest true "Email notification data"
// @Success 200 {object} map[string]interface{} "Email notification sent successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/email [post]
func (h *NotificationHandler) SendEmailNotification(c *gin.Context) {
	var req entity.EmailNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.notificationUseCase.SendEmailNotification(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email notification sent successfully"})
}

// GetUserNotifications godoc
// @Summary Get user notifications
// @Description Get notifications for a specific user with pagination
// @Tags Notifications
// @Security BearerAuth
// @Produce json
// @Param user_id path string true "User ID"
// @Param limit query int false "Limit number of results" default(10)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} map[string]interface{} "User notifications retrieved successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/user/{user_id} [get]
func (h *NotificationHandler) GetUserNotifications(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	limitStr := c.DefaultQuery("limit", "10")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	notifications, err := h.notificationUseCase.GetUserNotifications(c.Request.Context(), userID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"notifications": notifications})
}

// GetNotificationByID godoc
// @Summary Get notification by ID
// @Description Get a specific notification by its ID
// @Tags Notifications
// @Security BearerAuth
// @Produce json
// @Param id path string true "Notification ID"
// @Success 200 {object} map[string]interface{} "Notification retrieved successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 404 {object} map[string]interface{} "Notification not found"
// @Router /notifications/{id} [get]
func (h *NotificationHandler) GetNotificationByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
		return
	}

	notification, err := h.notificationUseCase.GetNotificationByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"notification": notification})
}

// MarkAsRead godoc
// @Summary Mark notification as read
// @Description Mark a notification as read/viewed
// @Tags Notifications
// @Security BearerAuth
// @Produce json
// @Param id path string true "Notification ID"
// @Success 200 {object} map[string]interface{} "Notification marked as read"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/{id}/read [put]
func (h *NotificationHandler) MarkAsRead(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
		return
	}

	err = h.notificationUseCase.MarkAsRead(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Notification marked as read"})
}