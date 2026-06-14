package repository

import (
	"Identity_Provider/internal/models"
	"context"
	"database/sql"
	"errors"
)

// PostgresUserRepository is a struct that holds the actual database connection pool.
type PostgresUserRepository struct {
	db *sql.DB
}

// but it is typed to satisfy the UserRepository interface.
func NewPostgresUserRepository(db *sql.DB) UserRepository {
	return &PostgresUserRepository{db :db}
}

// CreateUser executes the INSERT statement.
func (r *PostgresUserRepository) CreateUser(ctx context.Context, user *models.User) error {
	query := `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, token_version, created_at, updated_at`

	// QueryRowContext allows to execute the query and instantly scan the auto-generated
	// fields (like the UUID and timestamps) right back into our user struct in memory.
	err := r.db.QueryRowContext(ctx, query, user.Email, user.PasswordHash, user.Role).Scan(&user.ID, &user.TokenVersion, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return err
	}

	return nil
}

// GetUserByEmail executes the SELECT statement.
func (r *PostgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, email, password_hash, role, token_version, created_at, updated_at FROM users WHERE email = $1`

	var user models.User

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.TokenVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// IncrementTokenVersion acts as the "Kill Switch"
func (r *PostgresUserRepository) IncrementTokenVersion(ctx context.Context, userID string) error {
	query := `UPDATE users SET token_version = token_version + 1 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}