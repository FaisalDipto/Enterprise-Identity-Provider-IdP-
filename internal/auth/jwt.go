package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
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

// LoadRSAKeys reads the private and public keys from the filesystem.
func LoadRSAKeys(privateKeyPath, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	
	// ---------------------------------------------------------
	// 1. Read and parse the Private Key
	// ---------------------------------------------------------
	privBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	
	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil {
		return nil, nil, errors.New("failed to find any PEM block in private key file")
	}

	var privateKey *rsa.PrivateKey

	// The Upgraded Format Check
	if privBlock.Type == "RSA PRIVATE KEY" {
		// Legacy PKCS#1 Format
		privateKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
	} else if privBlock.Type == "PRIVATE KEY" {
		// Modern PKCS#8 Format (OpenSSL 3+)
		keyInterface, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		// Type assert the generic interface back into an RSA Private Key
		var ok bool
		privateKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("not an RSA private key inside PKCS#8 block")
		}
	} else {
		// If a hacker tries to pass an ECDSA or Ed25519 key, we lock them out
		return nil, nil, errors.New("unsupported private key type: " + privBlock.Type)
	}


	// ---------------------------------------------------------
	// 2. Read and parse the Public Key
	// ---------------------------------------------------------
	pubBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}

	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		return nil, nil, errors.New("failed to decode PEM block containing public key")
	}
	
	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("not an RSA public key")
	}

	return privateKey, publicKey, nil
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