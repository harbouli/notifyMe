package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server       ServerConfig
	Database     DatabaseConfig
	JWT          JWTConfig
	Notification NotificationConfig
	Auth0        Auth0Config
}

type ServerConfig struct {
	Port string
	Host string
	Mode string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type JWTConfig struct {
	SecretKey            string
	AccessTokenExpiry    time.Duration
	RefreshTokenExpiry   time.Duration
}

type NotificationConfig struct {
	Firebase FirebaseConfig
	Email    EmailConfig
}

type FirebaseConfig struct {
	CredentialsPath string
	Enabled         bool
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
	Enabled      bool
}

type Auth0Config struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Audience     string
	Enabled      bool
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
	}

	accessExpiry, _ := strconv.Atoi(getEnv("JWT_ACCESS_EXPIRY_MINUTES", "15"))
	refreshExpiry, _ := strconv.Atoi(getEnv("JWT_REFRESH_EXPIRY_HOURS", "168"))
	smtpPort, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))

	return &Config{
		Server: ServerConfig{
			Port: getEnv("SERVER_PORT", "8080"),
			Host: getEnv("SERVER_HOST", "localhost"),
			Mode: getEnv("GIN_MODE", "debug"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", "postgres"),
			DBName:   getEnv("DB_NAME", "hexagon_db"),
			SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		},
		JWT: JWTConfig{
			SecretKey:            getEnv("JWT_SECRET", "your-secret-key-change-this-in-production"),
			AccessTokenExpiry:    time.Duration(accessExpiry) * time.Minute,
			RefreshTokenExpiry:   time.Duration(refreshExpiry) * time.Hour,
		},
		Notification: NotificationConfig{
			Firebase: FirebaseConfig{
				CredentialsPath: getEnv("FIREBASE_CREDENTIALS_PATH", ""),
				Enabled:         getEnv("FIREBASE_ENABLED", "false") == "true",
			},
			Email: EmailConfig{
				SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
				SMTPPort:     smtpPort,
				SMTPUsername: getEnv("SMTP_USERNAME", ""),
				SMTPPassword: getEnv("SMTP_PASSWORD", ""),
				FromEmail:    getEnv("FROM_EMAIL", ""),
				FromName:     getEnv("FROM_NAME", "NotifyMe"),
				Enabled:      getEnv("EMAIL_ENABLED", "false") == "true",
			},
		},
		Auth0: Auth0Config{
			Domain:       getEnv("AUTH0_DOMAIN", ""),
			ClientID:     getEnv("AUTH0_CLIENT_ID", ""),
			ClientSecret: getEnv("AUTH0_CLIENT_SECRET", ""),
			Audience:     getEnv("AUTH0_AUDIENCE", ""),
			Enabled:      getEnv("AUTH0_ENABLED", "false") == "true",
		},
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}