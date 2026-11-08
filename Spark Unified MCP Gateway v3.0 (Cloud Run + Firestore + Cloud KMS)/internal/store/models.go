package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when an entity does not exist or has expired.
	ErrNotFound = errors.New("entity not found")
	// ErrConflict is returned when an optimistic lock or CAS condition fails.
	ErrConflict = errors.New("optimistic lock or CAS conflict")
	// ErrAlreadyConsumed is returned when a single-use token or code is reused.
	ErrAlreadyConsumed = errors.New("token or code has already been consumed")
	// ErrClientCapExceeded is returned when max registered clients limit is reached.
	ErrClientCapExceeded = errors.New("maximum registered OAuth clients limit reached")
)

// OAuthClient represents a registered OAuth 2.1 client (RFC 7591).
type OAuthClient struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	ClientName   string    `json:"client_name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"` // Native TTL
}

// AuthCode represents a single-use authorization code.
type AuthCode struct {
	Code                string            `json:"code"`
	ClientID            string            `json:"client_id"`
	AdminEmail          string            `json:"admin_email"`
	RedirectURI         string            `json:"redirect_uri"`
	CodeChallenge       string            `json:"code_challenge"`
	CodeChallengeMethod string            `json:"code_challenge_method"`
	Resource            string            `json:"resource"`
	Scopes              map[string]string `json:"scopes"` // connector -> mode
	CreatedAt           time.Time         `json:"created_at"`
	ExpiresAt           time.Time         `json:"expires_at"` // Native TTL
	Used                bool              `json:"used"`
}

// RefreshTokenRecord represents a hashed rotating OAuth refresh token.
type RefreshTokenRecord struct {
	TokenHash  string            `json:"token_hash"` // SHA-256
	FamilyID   string            `json:"family_id"`
	ClientID   string            `json:"client_id"`
	AdminEmail string            `json:"admin_email"`
	Resource   string            `json:"resource"`
	Scopes     map[string]string `json:"scopes"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"` // Native TTL
	Revoked    bool              `json:"revoked"`
}

// OAuthState represents CSRF state for upstream 3LO OAuth broker handshakes.
type OAuthState struct {
	State        string    `json:"state"`
	Provider     string    `json:"provider"`
	Mode         string    `json:"mode"`
	AdminEmail   string    `json:"admin_email"`
	CodeVerifier string    `json:"code_verifier,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"` // Native TTL
}

// EncryptedConnection represents encrypted credentials and distributed refresh lease state.
type EncryptedConnection struct {
	UserID         string    `json:"user_id"`
	Provider       string    `json:"provider"`
	WrappedDEK     []byte    `json:"wrapped_dek"`
	Nonce          []byte    `json:"nonce"`
	Ciphertext     []byte    `json:"ciphertext"`
	KMSKeyVersion  string    `json:"kms_key_version"`
	LeaseHolder    string    `json:"lease_holder,omitempty"`
	LeaseExpiresAt time.Time `json:"lease_expires_at,omitempty"`
	Version        int64     `json:"version"`
	UpdateTime     time.Time `json:"update_time"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Store is the persistence interface for state, credentials, and distributed leases.
type Store interface {
	// OAuth Clients
	SaveOAuthClient(ctx context.Context, client *OAuthClient) error
	GetOAuthClient(ctx context.Context, clientID string) (*OAuthClient, error)
	CountActiveClients(ctx context.Context) (int, error)

	// Auth Codes
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAndConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error)

	// Refresh Tokens
	SaveRefreshToken(ctx context.Context, record *RefreshTokenRecord) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenRecord, error)
	ConsumeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeTokenFamily(ctx context.Context, familyID string) error

	// OAuth States
	SaveOAuthState(ctx context.Context, state *OAuthState) error
	GetAndConsumeOAuthState(ctx context.Context, state string) (*OAuthState, error)

	// Encrypted Connections
	GetConnection(ctx context.Context, userID, provider string) (*EncryptedConnection, error)
	SaveConnection(ctx context.Context, conn *EncryptedConnection) error
	DeleteConnection(ctx context.Context, userID, provider string) error
	ListConnections(ctx context.Context, userID string) ([]*EncryptedConnection, error)

	// Distributed CAS Refresh Leases
	AcquireConnectionLease(ctx context.Context, userID, provider, instanceID string, leaseDuration time.Duration) (*EncryptedConnection, bool, error)
	ReleaseConnectionLease(ctx context.Context, userID, provider, instanceID string, newConn *EncryptedConnection) error
}
