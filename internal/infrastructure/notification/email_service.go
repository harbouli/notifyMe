package notification

import (
	"crypto/tls"
	"fmt"

	"gopkg.in/gomail.v2"
)

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
}

type EmailService struct {
	config *EmailConfig
}

func NewEmailService(config *EmailConfig) *EmailService {
	return &EmailService{
		config: config,
	}
}

func (e *EmailService) SendEmail(to, subject, body string) error {
	message := gomail.NewMessage()
	message.SetHeader("From", fmt.Sprintf("%s <%s>", e.config.FromName, e.config.FromEmail))
	message.SetHeader("To", to)
	message.SetHeader("Subject", subject)
	message.SetBody("text/html", body)

	dialer := gomail.NewDialer(e.config.SMTPHost, e.config.SMTPPort, e.config.SMTPUsername, e.config.SMTPPassword)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := dialer.DialAndSend(message); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (e *EmailService) SendEmailWithAttachment(to, subject, body string, attachmentPath string) error {
	message := gomail.NewMessage()
	message.SetHeader("From", fmt.Sprintf("%s <%s>", e.config.FromName, e.config.FromEmail))
	message.SetHeader("To", to)
	message.SetHeader("Subject", subject)
	message.SetBody("text/html", body)
	message.Attach(attachmentPath)

	dialer := gomail.NewDialer(e.config.SMTPHost, e.config.SMTPPort, e.config.SMTPUsername, e.config.SMTPPassword)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := dialer.DialAndSend(message); err != nil {
		return fmt.Errorf("failed to send email with attachment: %w", err)
	}

	return nil
}

func (e *EmailService) SendBulkEmail(recipients []string, subject, body string) error {
	message := gomail.NewMessage()
	message.SetHeader("From", fmt.Sprintf("%s <%s>", e.config.FromName, e.config.FromEmail))
	message.SetHeader("Subject", subject)
	message.SetBody("text/html", body)

	dialer := gomail.NewDialer(e.config.SMTPHost, e.config.SMTPPort, e.config.SMTPUsername, e.config.SMTPPassword)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	sender, err := dialer.Dial()
	if err != nil {
		return fmt.Errorf("failed to dial SMTP server: %w", err)
	}
	defer sender.Close()

	for _, recipient := range recipients {
		message.SetHeader("To", recipient)
		if err := gomail.Send(sender, message); err != nil {
			return fmt.Errorf("failed to send email to %s: %w", recipient, err)
		}
		message.Reset()
		message.SetHeader("From", fmt.Sprintf("%s <%s>", e.config.FromName, e.config.FromEmail))
		message.SetHeader("Subject", subject)
		message.SetBody("text/html", body)
	}

	return nil
}