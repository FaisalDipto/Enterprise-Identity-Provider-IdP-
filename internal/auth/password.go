package auth

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidCredentials is returned when a password verificiation fails.
	// We use a generic error message so we don't leak wheather the email or password was wrong.
	ErrInvalidCredentials = errors.New("invalid email or password")
)

// HashPassword take a plaintext password, generates a unique salt, and   applies the bcrypt algorithm at the DefaultCost (10) to generate a secure hash string.
func HashPassword(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), err
}

// CheckPassword securely compares a plaintext password against a stored bcrypt hash.
// It extracts the salt and cost from the hash string automatically to perform the check
func CheckPassword(plaintext, storedHash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(plaintext))
	if err != nil {
		// If the error is bcrypt.ErrMismatchHashAndPassword, we return our generic error
		// to prevent username enumeration attacks.
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}
		// Return any other critical errors (like a malformed hash string in the DB)
		return err
	}
	return nil
}