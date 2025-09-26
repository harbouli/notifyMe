package notification

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"
)

type FirebaseService struct {
	client *messaging.Client
}

func NewFirebaseService(credentialsPath string) (*FirebaseService, error) {
	opt := option.WithCredentialsFile(credentialsPath)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase app: %w", err)
	}

	client, err := app.Messaging(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase messaging client: %w", err)
	}

	return &FirebaseService{
		client: client,
	}, nil
}

func (f *FirebaseService) SendNotification(ctx context.Context, token, title, body string, data map[string]string) error {
	message := &messaging.Message{
		Token: token,
		Notification: &messaging.Notification{
			Title: title,
			Body:  body,
		},
		Data: data,
	}

	_, err := f.client.Send(ctx, message)
	if err != nil {
		return fmt.Errorf("failed to send push notification: %w", err)
	}

	return nil
}

func (f *FirebaseService) SendMulticastNotification(ctx context.Context, tokens []string, title, body string, data map[string]string) (*messaging.BatchResponse, error) {
	message := &messaging.MulticastMessage{
		Tokens: tokens,
		Notification: &messaging.Notification{
			Title: title,
			Body:  body,
		},
		Data: data,
	}

	response, err := f.client.SendMulticast(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("failed to send multicast notification: %w", err)
	}

	return response, nil
}

func (f *FirebaseService) SubscribeToTopic(ctx context.Context, tokens []string, topic string) (*messaging.TopicManagementResponse, error) {
	response, err := f.client.SubscribeToTopic(ctx, tokens, topic)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic: %w", err)
	}

	return response, nil
}

func (f *FirebaseService) UnsubscribeFromTopic(ctx context.Context, tokens []string, topic string) (*messaging.TopicManagementResponse, error) {
	response, err := f.client.UnsubscribeFromTopic(ctx, tokens, topic)
	if err != nil {
		return nil, fmt.Errorf("failed to unsubscribe from topic: %w", err)
	}

	return response, nil
}