package repository

import (
	"Identity_Provider/internal/models"
	"context"
	"time"
)

// UserRepository defines the strict contract any database must follow.
// Notice we pass context.Context to every method so we can enforce timeouts.
type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	IncrementTokenVersion(ctx context.Context, userID string) error
}

// RefreshTokenRepository defines the strict contract for session management.
type RefreshTokenRepository interface {
	CreateToken(ctx context.Context, token *models.RefreshToken) error
	GetTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	DeleteToken(ctx context.Context, tokenHash string) error
	DeleteAllTokensForUser(ctx context.Context, userID string) error
}

// RevokedTokenRepository defines how we interact with the Denylist.
type RevokedTokenRepository interface {
	// RevokeToken adds a compromised token's signature to the Denylist.
	RevokeToken(ctx context.Context, signature string, ExpiresAt time.Time) error

	// IsTokenRevoked checks if a signature exists in the Denylist.
	IsTokenRevoked(ctx context.Context, signature string) (bool, error)
}