package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------
// 1. JWT SCHEMA & CONTEXT
// ---------------------------------------------------------
type CustomClaims struct {
	UserID string `json:"user_id"`
	Role   string	`json:"role"`
	jwt.RegisteredClaims
}

type contextKey string
const UserContextKey contextKey = "user-claims"

// ---------------------------------------------------------
// 2. THE KEY LOADER
// ---------------------------------------------------------
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	pubBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return publicKey, nil
}

// ---------------------------------------------------------
// 3. THE STATELESS BOUNCER (Middleware)
// ---------------------------------------------------------
func RequireAuth(publicKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// 1. Grab the token from Header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
				return
			}
			tokenStr := parts[1]

			// 2.Mathematically verify the token using ONLY the Public Key
			token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token)(interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, errors.New("unexpected siging method")
				}
				return publicKey, nil
			})

			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// 3. Extract the Claims and inject into context
			if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
				ctx := context.WithValue(r.Context(), UserContextKey, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
			}	else {
				http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			}
		})
	}
}

// ---------------------------------------------------------
// 4. THE PROTECTED HANDLERS
// ---------------------------------------------------------
func ClassifiedHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Unzip the context using our secure key
	rawData := r.Context().Value(UserContextKey)

	// 2. Type assert into our CustomClaims struct
	claims, ok := rawData.(*CustomClaims)
	if !ok {
		http.Error(w, "Server error: Invalid context data", http.StatusInternalServerError)
		return
	}

	// 3. Construct the highly restricted payload using the verified identity
	response := fmt.Sprintf(`{
	"classification": "TOP SECRET",
	"agent_id": "%s",
	"clearance_level": "%s",
	"directive": "Operation Midnight is a go. The package is secure in Dhaka."
	}`, claims.UserID, claims.Role)

	// 4. Serve the data
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// ---------------------------------------------------------
// 5. THE SERVER ENGINE
// ---------------------------------------------------------
func main() {
	// A. Load the Public Key into memory before the server starts
	publicKey, err := LoadPublicKey("./public.pem")
	if err != nil {
		log.Fatalf("CRITICAL: Failed to load public key: %v", err)
	}

	mux := http.NewServeMux()

	// B. Public Route (No clearance needed)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Diplomatic Dispatch Service in Online.\n"))
	})

	// C. Protected Route (Require RSA-Verified JWT)
	classifiedRoute := http.HandlerFunc(ClassifiedHandler)
	mux.Handle("/api/classified", RequireAuth(publicKey)(classifiedRoute))

	// D. Start the Server
	fmt.Println("Dispatch Service securely booted on port 8081...")
	log.Fatal(http.ListenAndServe(":8081", mux))
}