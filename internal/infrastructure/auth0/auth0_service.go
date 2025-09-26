package auth0

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"notifyMe/internal/domain/entity"
	"notifyMe/internal/domain/repository"

	"github.com/auth0/go-auth0/management"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Auth0Service struct {
	domain       string
	clientID     string
	clientSecret string
	audience     string
	management   *management.Management
}

type Auth0Config struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Audience     string
}

type Auth0User struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func NewAuth0Service(config *Auth0Config) (*Auth0Service, error) {
	if config.Domain == "" || config.ClientID == "" || config.ClientSecret == "" {
		return nil, errors.New("Auth0 configuration is incomplete")
	}

	// Initialize Auth0 Management API client
	mgmt, err := management.New(
		config.Domain,
		management.WithClientCredentials(context.TODO(), config.ClientID, config.ClientSecret),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Auth0 management client: %w", err)
	}

	return &Auth0Service{
		domain:       config.Domain,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		audience:     config.Audience,
		management:   mgmt,
	}, nil
}

// ValidateAuth0Token validates an Auth0 JWT token and returns user information
func (a *Auth0Service) ValidateAuth0Token(tokenString string) (*Auth0User, error) {
	// Parse the token without verification first to get the header
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("token header missing key ID")
	}

	// Get the JWKS from Auth0
	jwks, err := a.getJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Find the key with matching kid
	var publicKey interface{}
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			publicKey, err = key.GetPublicKey()
			if err != nil {
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}
			break
		}
	}

	if publicKey == nil {
		return nil, errors.New("no matching key found")
	}

	// Validate the token with the public key
	validatedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !validatedToken.Valid {
		return nil, errors.New("token is invalid")
	}

	// Extract claims
	claims, ok := validatedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse token claims")
	}

	// Validate audience if specified
	if a.audience != "" {
		if aud, ok := claims["aud"]; ok {
			if audStr, ok := aud.(string); ok {
				if audStr != a.audience {
					return nil, errors.New("invalid audience")
				}
			}
		}
	}

	// Extract user information
	auth0User := &Auth0User{}
	if sub, ok := claims["sub"].(string); ok {
		auth0User.Sub = sub
	}
	if email, ok := claims["email"].(string); ok {
		auth0User.Email = email
	}
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		auth0User.EmailVerified = emailVerified
	}
	if name, ok := claims["name"].(string); ok {
		auth0User.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		auth0User.GivenName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		auth0User.FamilyName = familyName
	}
	if picture, ok := claims["picture"].(string); ok {
		auth0User.Picture = picture
	}
	if locale, ok := claims["locale"].(string); ok {
		auth0User.Locale = locale
	}

	return auth0User, nil
}

// GetOrCreateUserFromAuth0 gets or creates a user from Auth0 token
func (a *Auth0Service) GetOrCreateUserFromAuth0(ctx context.Context, auth0User *Auth0User, userRepo repository.UserRepository) (*entity.User, error) {
	// Try to find user by Auth0 sub ID (stored in external_id field we'll add)
	user, err := userRepo.GetByExternalID(ctx, auth0User.Sub)
	if err == nil {
		// User exists, update their info
		user.Email = auth0User.Email
		user.FirstName = auth0User.GivenName
		user.LastName = auth0User.FamilyName
		user.UpdatedAt = time.Now()
		
		if err := userRepo.Update(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		return user, nil
	}

	// Try to find user by email
	user, err = userRepo.GetByEmail(ctx, auth0User.Email)
	if err == nil {
		// User exists with this email, link the Auth0 account
		user.ExternalID = auth0User.Sub
		user.ExternalProvider = "auth0"
		user.FirstName = auth0User.GivenName
		user.LastName = auth0User.FamilyName
		user.UpdatedAt = time.Now()
		
		if err := userRepo.Update(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to link Auth0 account: %w", err)
		}
		return user, nil
	}

	// Create new user
	username := auth0User.Email
	if username == "" {
		username = auth0User.Sub
	}

	newUser := &entity.User{
		ID:               uuid.New(),
		Email:            auth0User.Email,
		Username:         username,
		PasswordHash:     "", // No password for OAuth users
		FirstName:        auth0User.GivenName,
		LastName:         auth0User.FamilyName,
		ExternalID:       auth0User.Sub,
		ExternalProvider: "auth0",
		IsActive:         true,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := userRepo.Create(ctx, newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return newUser, nil
}

// GetAuthorizationURL returns the Auth0 authorization URL for OAuth flow
func (a *Auth0Service) GetAuthorizationURL(redirectURI, state string) string {
	baseURL := fmt.Sprintf("https://%s/authorize", a.domain)
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {a.clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile email"},
		"state":         {state},
		"connection":    {"google-oauth2"}, // Force Google OAuth
	}

	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

// ExchangeCodeForToken exchanges authorization code for access token
func (a *Auth0Service) ExchangeCodeForToken(code, redirectURI string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth/token", a.domain)
	
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// JWKS represents JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// GetPublicKey extracts the public key from JWK
func (j *JWK) GetPublicKey() (interface{}, error) {
	if len(j.X5c) == 0 {
		return nil, errors.New("no certificate found in JWK")
	}

	cert := "-----BEGIN CERTIFICATE-----\n" + j.X5c[0] + "\n-----END CERTIFICATE-----"
	
	// Use the golang-jwt library to parse the certificate
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key from certificate: %w", err)
	}
	
	return key, nil
}

// getJWKS fetches the JSON Web Key Set from Auth0
func (a *Auth0Service) getJWKS() (*JWKS, error) {
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", a.domain)
	
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	return &jwks, nil
}