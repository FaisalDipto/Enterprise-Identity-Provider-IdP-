package repository

import (
	"context"
	"Identity_Provider/internal/models"
)

// UserRepository defines the strict contract any database must follow.
// Notice we pass context.Context to every method so we can enforce timeouts.
type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	IncrementTokenVersion(ctx context.Context, userID string) error
}

// RefreshTokenRepository defines the strict contract for session management.
type RefreshTokenRepository interface {
	CreateToken(ctx context.Context, token *models.RefreshToken) error
	GetTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	DeleteToken(ctx context.Context, tokenHash string) error
	DeleteAllTokensForUser(ctx context.Context, userID string) error
}