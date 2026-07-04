package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// GenerateRefreshToken creates a secure random string and its SHA-256 hash.
// It returns BOTH the raw string (for the user) and the hash (for the DB).
func GenerateRefreshToken() (string, string, error) {
	// 1. Create a byte slice to hold 32 random bytes
	randomBytes := make([]byte, 32)

	// 2. Fill the slice with cryptographically secure random data from the OS
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", "", err
	}

	// 3. Convert the random bytes into a URL-safe string (The Raw Token)
	// We use Base64Url encoding so it can be safely placed in an HTTP Cookie
	rawToken := base64.URLEncoding.EncodeToString(randomBytes)

	// 4. Hash the raw token using SHA-256 (The Database Hash)
	// SHA-256 returns a 32-byte array, which we convert to a readable Hex string
	hashBytes := sha256.Sum224([]byte(rawToken))
	tokenHash := hex.EncodeToString(hashBytes[:])

	return rawToken, tokenHash, nil
}

// HashToken is a helper function.
// When the user sends their raw token back to us to log in,
// we use this to hash it so we can search the database.
func HashToken(rawToken string) string {
	hashBytes := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hashBytes[:])
}