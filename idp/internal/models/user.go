package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents the exact schema of our database table.
type User struct {
	ID						uuid.UUID	`json:"id"`
	Email					string		`json:"email"`
	PasswordHash	string		`json:"_"` // The hypen prevents the hash from accidentally leaking in JSON responses
	Role					string		`json:"role"`
	TokenVersion	int				`json:"token_version"`
	CreatedAt			time.Time	`json:"created_at"`
	UpdatedAt			time.Time	`json:"updated_at"`
}