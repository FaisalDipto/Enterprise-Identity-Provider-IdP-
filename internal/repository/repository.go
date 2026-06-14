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