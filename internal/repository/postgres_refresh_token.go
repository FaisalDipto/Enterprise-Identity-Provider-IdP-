package repository

import (
	"context"
	"database/sql"
	"errors"

	"Identity_Provider/internal/models"
)

type PostgresRefreshTokenRespository struct {
	db *sql.DB
}

func NewPostgresRefreshTokenRepository(db *sql.DB) RefreshTokenRepository {
	return &PostgresRefreshTokenRespository{db: db}
}

// CreateToken saves the newly hashed refresh token into the database.
func (r * PostgresRefreshTokenRespository) CreateToken(ctx context.Context, token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`

	err := r.db.QueryRowContext(ctx, query, token.UserID, token.TokenHash, token.ExpiresAt).Scan(&token.ID, &token.CreatedAt)

	return err
}

// GetTokenByHash searches for an existing token.
func (r *PostgresRefreshTokenRespository) GetTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1`

	var t models.RefreshToken
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid refresh token")
		}
		return nil, err
	}

	return &t, nil
}

// DeleteToken burns the token so it can never be used again (Refresh Token Rotation).
func (r *PostgresRefreshTokenRespository) DeleteToken(ctx context.Context, tokenHash string) error {
	query := `
		DELETE FROM refresh_tokens WHERE token_hash = $1`
		_, err := r.db.ExecContext(ctx, query, tokenHash)
		return err
}

// DeleteAllTokensForUser is our security tripwire. If a breach is detected, we wipe all active sessions.
func (r *PostgresRefreshTokenRespository) DeleteAllTokensForUser(ctx context.Context, userID string) error {
	query := `
		DELETE FROM refresh_tokens WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}