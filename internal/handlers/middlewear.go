package handlers

import (
	"Identity_Provider/internal/auth"
	"context"
	"net/http"
	"strings"
)

// We define a custom type for context keys to prevent accidental collisions
// with other packages that might put data into the request context.
type contextKey string
const UserContextKey contextKey = "user_claims"

// RequireAuth is the middleware function. It takes our tokenManager as a dependency
// and returns a standard Go middleware signature: func(http.Handler) http.Handler
func RequireAuth(tm *auth.TokenManager) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// 1. Extract the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
				return
			}

			// 2. Validate the format: "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
				return
			}
			tokenString := parts[1]

			// 3. Verify the token using our Phase 1 RSA engine
			claims, err := tm.VerifyToken(tokenString)
			if err != nil {
				// If the token is expired, tampered with, or invalid, the bouncer stops them here.
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// 4. Inject the verified claims into the HTTP Request Context
			// This allows the next handler to know EXACTLY who made the request!
			ctx := context.WithValue(r.Context(), UserContextKey, claims)

			// 5. Create a new request with the updated context
			reqWithContext := r.WithContext(ctx)

			// 6. Let the request pass through to the protected route
			next.ServeHTTP(w, reqWithContext)
		})
	}
}