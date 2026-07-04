package repository

import (
	"context"
	"database/sql"
	"time"
)

type postgresRevokedTokenRepository struct {
	db *sql.DB
}

// NewPostgresRevokedTokenRepository creates a new instance linked to your connection pool.
func NewPostgresRevokedTokenRepository(db *sql.DB) RevokedTokenRepository {
	return &postgresRevokedTokenRepository{db: db}
}

// RevokeToken inserts the signature and its natural expiration time into database.
func (r *postgresRevokedTokenRepository) RevokeToken(ctx context.Context, signature string, expiresAt time.Time) error {
	query := `
		INSERT INTO revoked_tokens (token_signature, expires_at)
		VALUES ($1, $2)
		ON CONFLICT (token_signature) DO NOTHING
	`
	// We use ExexContext to respect API timeouts
	_, err := r.db.ExecContext(ctx, query, signature, expiresAt)
	return err
}

// IsTokenRevoked queries the index to see if the token signature is banned.
func (r *postgresRevokedTokenRepository) IsTokenRevoked(ctx context.Context, signature string) (bool, error) {
	query := `
		SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_signature = $1)
	`

	var isRevoked bool
	err := r.db.QueryRowContext(ctx, query, signature).Scan(&isRevoked)
	if err != nil {
		// If the database fails, we fail closed (secure)
		return true, err
	}

	return isRevoked, nil
}