package auth

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims defines the custom payload structure inside our JWT.
// We inherit standard claims via jwt.RegisteredClaims.
type CustomClaims struct {
	UserID 	string `json:"user_id"`
	Role 		string `json:"role"`
	jwt.RegisteredClaims
}

// TokenManager handles the generation and verification of asymmetric tokens.
type TokenManager struct {
	publicKey *rsa.PublicKey
	privateKey *rsa.PrivateKey
	issuer string
}

// NewTokenManager initializes a manager with the cryptographic RSA keys.
func NewTokenManager(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey, issuer string) *TokenManager {
	return &TokenManager{
		publicKey: pubKey,
		privateKey: privKey,
		issuer: issuer, 
	}
}

// GenerateAccessToken mints a short-lived access token signed with the RSA Private Key.
func(tm *TokenManager) GenerateAccessToken(userId, role string, duration time.Duration) (string, error) {
	claims := CustomClaims{
		UserID: userId,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer: tm.issuer,
		},
	}

	// Use SigningMethodRS256 indicating Asymmetric RSA signing
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims) 

	// Sign the token using the private key
	signedString, err := token.SignedString(tm.privateKey)
	if err != nil {
		return "", err
	}

	return signedString, nil
}

// VerifyToken validates an incoming token string against our RSA Public Key.
func (tm *TokenManager) VerifyToken(tokenStr string) (*CustomClaims, error) {
	// Parse back the token with custom claims schema
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Crucial security check: Ensure the signing method is exactly what we expect (RS256)
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		// Return the Public Key to the parser to mathematically verify the signature
		return tm.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Extract the verified claims out of the token container
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("Invalid token claims")
}