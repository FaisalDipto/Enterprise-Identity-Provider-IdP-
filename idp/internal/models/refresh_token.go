package models

import (
	"time"
	"github.com/google/uuid"
)

// RefreshToken maps exactly to our new PostgreSQL table.
type RefreshToken struct {
	ID	uuid.UUID				`json:"id"`
	UserID	uuid.UUID		`json:"user_id"`
	TokenHash string		`json:"-"`
	ExpiresAt time.Time	`json:"expires_at"`
	CreatedAt time.Time	`json:"created_at"`
}