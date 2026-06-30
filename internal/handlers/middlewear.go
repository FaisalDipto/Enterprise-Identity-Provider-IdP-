package handlers

import (
	"Identity_Provider/internal/auth"
	"Identity_Provider/internal/repository"
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
func RequireAuth(tm *auth.TokenManager, revokedRepo repository.RevokedTokenRepository) func(http.Handler) http.Handler {

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

			// ---------------------------------------------------------
			// 🔥 THE NEW KILL SWITCH (MODULE 5.1) 🔥
			// ---------------------------------------------------------

			// 3a. Extract the signature (using the helper we wrote earlier)
			signature, err := auth.ExtractSignature(tokenString)
			if err != nil {
				http.Error(w, "Malformed token format", http.StatusUnauthorized)
				return
			}

			// 3b. Check the Denylist in the database
			isRevoked, err := revokedRepo.IsTokenRevoked(r.Context(), signature)
			if err != nil {
				http.Error(w, "Internal server error during security check", http.StatusInternalServerError)
				return
			}

			// 3c. Drop the hammer if the token in banned
			if isRevoked {
				http.Error(w, "Token has been revoked. Please log in again.", http.StatusUnauthorized)
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

// RequireRole is an RBAC middleware. It takes a list of allowed roles.
// Note: This MUST be places AFTER RequireAuth in router chain.
func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// 1. Unzip the backpack (We assume RequireAuth already put it there)
			rawData := r.Context().Value(UserContextKey)
			if rawData == nil {
				http.Error(w, "Unauthorized: No user context found", http.StatusUnauthorized)
				return
			}

			// 2. Type assert to our specific CustomClaims struct
			claims, ok := rawData.(*auth.CustomClaims)
			if !ok {
				http.Error(w, "Internal server error: Invalid claims", http.StatusInternalServerError)
				return
			}

			// 3. Check if the user's role matches any of the allowed roles
			hasPermission := false
			for _, role := range allowedRoles {
				if claims.Role == role {
					hasPermission = true
					break
				}
			}

			// 4. The Decision Gate
			if !hasPermission {
				// We return 403 Forbidden (I know who you are, but you don't have permission)
				// NOT 401 Unauthorized (I don't know who you are)
				http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
				return
			}

			// 5. Success! Pass the request to the final handler
			next.ServeHTTP(w, r)
		})
	}
}

// ProfileHandler handles GET /api/profile (Protected Route)
func ProfileHandler(w http.ResponseWriter, r *http.Request) {

	// 1. Unzip the backpack using our secure, custom type key
	rawData := r.Context().Value(UserContextKey)

	// 2. The Type Assertion: Force the generic data into our specific struct shape
	claims, ok := rawData.(*auth.CustomClaims)
	if !ok {
		// If someone tempered with the context, or it's empty, kick them out
		http.Error(w, "Server error: Invalid context data", http.StatusInternalServerError)
		return
	}

	// 3. Success! We now have strongly-typed access to the JWT payload
	w.Write([]byte("Welcome to your profile, User ID: " + claims.UserID))
}

// AdminDashBoardHandler handles GET /api/admin (protected)
func AdminDashBoardHandler(w http.ResponseWriter, r *http.Request) {
	rawData := r.Context().Value(UserContextKey)

	claims, ok := rawData.(*auth.CustomClaims)
	if !ok {
		http.Error(w, "Server error: Invalid context data", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Welcome ADMIN!!!, Your id: " + claims.UserID))
}