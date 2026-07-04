package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"Identity_Provider/internal/auth"
	"Identity_Provider/internal/models"
	"Identity_Provider/internal/repository"
)

// AuthHandler holds the dependencies our HTTP routes need.
type AuthHandler struct {
	repo repository.UserRepository
	refreshTokenRepo repository.RefreshTokenRepository
	revokedRepo repository.RevokedTokenRepository
	tokenManager *auth.TokenManager
}

// NewAuthHandler is the constructor. Notice it asks for the Interface, not Postgres!
func NewAuthHandler(repo repository.UserRepository, rtr repository.RefreshTokenRepository,rev repository.RevokedTokenRepository,tm *auth.TokenManager) *AuthHandler {
	return &AuthHandler{
		repo: repo,
		refreshTokenRepo: rtr,
		revokedRepo: rev,
		tokenManager: tm,
	}
}

// ---------------------------------------------------------
// DATA TRANSFER OBJECTS (DTOs)
// We define strict structs for exactly what we expect in the request
// and exactly what we want to expose in the response.
// ---------------------------------------------------------

type RegisterRequest struct {
	Email 	 string `json:"email"`
	Password string	`json:"password"`
}

type RegisterResponse struct {
	ID 			string  `json:"id"`
	Email 	string	`json:"email"`
	Message string	`json:"message"`
}

// -----------------------------------------------------
// HTTP ROUTES
// -----------------------------------------------------

// Register handles POST /api/register
func (h *AuthHandler) Register (w http.ResponseWriter, r *http.Request) {
	log.Println("🚀 DOCKER CONTAINER REGISTER ROUTE HIT!")
	// 1. Enforce HTTP Method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Parse the incoming JSON payload into our Request DTO
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// 3. Hash the password using our Phase 1 Cryptography Engine
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("CRITICAL DB ERROR DURING REGISTER: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 4. Construct the User model for the database
	newUser := &models.User{
		Email: req.Email,
		PasswordHash: hashedPassword,
		Role: "user",
	}

	// 5. Save the user using our Phase 2 Repository
	err = h.repo.CreateUser(r.Context(), newUser)
	if err != nil {
		// If the database throws an error (e.g., Email already exists), we return a 409 Conflict
		http.Error(w, "Error from inside Docker!", http.StatusConflict)
		return
	}

	// 6. Construct a safe JSON response
	res := RegisterResponse{
		ID: newUser.ID.String(),
		Email: newUser.Email,
		Message: "User successfully registered",
	}

	// 7. Send the 201 Created HTTP status and the JSON response
	w.Header().Set("Content-Type", "application.json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

// ---------------------------------------------------------
// LOGIN DATA TRANSFER OBJECTS (DTOs)
// ---------------------------------------------------------

type LoginRequest struct {
	Email 	 string `json:"email"`
	Password string	`json:"password"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

// ---------------------------------------------------------
// Login handles POST /api/login
// ---------------------------------------------------------
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce HTTP Method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Parse the Request
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// 3. Fetch the User from PostgreSQL via the Interface
	user, err := h.repo.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 4. Verify the Password using our Phase 1 Crypto Engine
	err = auth.CheckPassword(req.Password, user.PasswordHash)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 5. Mint the Access Token (15-minute lifespan is the enterprise standard)
	// We inject the user.ID and user.Role straight into the JWT payload.
	tokenString, err := h.tokenManager.GenerateAccessToken(user.ID.String(), user.Role, 15*time.Minute)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// ================================
	// NEW: DUAL_TOKEN LOGIC
	// ================================

	// 6. Generate the Refresh Token Pair
	rawToken, _, err := auth.GenerateRefreshToken()
	if err != nil {
		log.Printf("CRITICAL LOGIN ERROR: %v", err)
		http.Error(w, "Failed to generate session", http.StatusInternalServerError)
		return
	}

	dbHash := auth.HashToken(rawToken)

	log.Printf("=== LOGIN WIRETAP ===")
	log.Printf("Raw Cookie Value Issued: %s", rawToken)
	log.Printf("Hash Saved to Database: %s", dbHash)

	// 7. Store the Hash in PostgreSQL (Expires in 7 days)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	newSession := &models.RefreshToken{
		UserID: user.ID,
		TokenHash: dbHash,
		ExpiresAt: expiresAt,
	}

	err = h.refreshTokenRepo.CreateToken(r.Context(), newSession)
	if err != nil {
		log.Printf("CRITICAL DB INSERT ERROR: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// 8. Construct the HttpOnly Cookie for the Raw Token
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token",
		Value: rawToken,
		Expires: expiresAt,
		HttpOnly: true,
		Secure: true,
		SameSite: http.SameSiteStrictMode,
		Path: "/api/refresh",
	})

	// 9. Send Response (Only the Access Token goes in the JSON)
	res := LoginResponse{
		AccessToken: tokenString,
	}

	// 10. Send the 200 OK and the Token
	w.Header().Set("Content-Type", "application.json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

	// =====================================
	// Refresh handles POST /api/refresh
	// =====================================

	func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
		// 1. Enforce HTTP Method
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 2. Extract the raw token from the HttpOnly Cookie
		cookie, err := r.Cookie("refresh_token")
		if err != nil {
			http.Error(w, "Missing session token", http.StatusUnauthorized)
			return
		}
		rawToken := cookie.Value

		// 3. Hash the raw token to interact with the Database
		tokenHash := auth.HashToken(rawToken)
		log.Printf("=== REFRESH WIRETAP ===")
		log.Printf("Raw Cookie Received: %s", rawToken)
		log.Printf("Hash Generated for DB Lookup: %s", tokenHash)

		// 4. Verify the token exists in the database
		storedToken, err := h.refreshTokenRepo.GetTokenByHash(r.Context(), tokenHash)
		if err != nil {
			// TRIPWIRE: If the token isn't in the database, it means it was either
			// never minted, or it was already burned by a previous request.
			http.Error(w, "Invalid or hijacked session", http.StatusUnauthorized)
			return
		}

		// 5. Check if the token expired naturally (7 days passed)
		if time.Now().After(storedToken.ExpiresAt) {
			// Clean up the dead token from the DB and reject the user
			h.refreshTokenRepo.DeleteToken(r.Context(), tokenHash)
			http.Error(w, "Session expired, please log in again", http.StatusUnauthorized)
			return
		}

		// 6. THE BURN: Refresh Token Rotation
		// We delete the old token immediately so it can never be used again.
		err = h.refreshTokenRepo.DeleteToken(r.Context(), tokenHash)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// 7. Fetch the fresh User data (to get their current role)
		// (Assumin GetUserByID was added to our UserRepository interface)
		user, err := h.repo.GetUserByID(r.Context(), storedToken.UserID.String())
		if err != nil {
			http.Error(w, "User no longer exists", http.StatusUnauthorized)
			return
		}

		// 8. Mint the new 15-Minute Access Token
		newAccessToken, err := h.tokenManager.GenerateAccessToken(user.ID.String(), user.Role, 15*time.Minute)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// 9. Mint the new 7-Day Refresh Token Pair
		newRawToken, _, err := auth.GenerateRefreshToken()
		if err != nil {
			http.Error(w, "Failed to generate session", http.StatusInternalServerError)
			return
		}

		newDbHash := auth.HashToken(newRawToken)

		// 10. Store the new Hash in PostgreSQL
		expiresAt := time.Now().Add(7 * 24 * time.Hour)
		newSession := &models.RefreshToken{
			UserID: user.ID,
			TokenHash: newDbHash,
			ExpiresAt: expiresAt,
		}
		h.refreshTokenRepo.CreateToken(r.Context(), newSession)

		// 11. Overwrite the old cookie with the new one
		http.SetCookie(w, &http.Cookie{
			Name: "refresh_token",
			Value: newRawToken,
			Expires: expiresAt,
			HttpOnly: true,
			Secure: true,
			SameSite: http.SameSiteStrictMode,
			Path: "/api/refresh",
		})

		// 12. Send the new Access Token in the JSON body
		res := LoginResponse{
			AccessToken: newAccessToken,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(res)
	}

// Logout invalidates the current access token by throwing it on the Denylist.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// 1. Pull the token string out of the Authorization header
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// 2.Extract the signature
	signature, err := auth.ExtractSignature(tokenString)
	if err != nil {
		http.Error(w, "Invalid token format", http.StatusBadRequest)
		return
	}

	// 3. Get the expiration time using your existing TokenManager
	claims, err := h.tokenManager.VerifyToken(tokenString)
	if err != nil {
		http.Error(w, "Could not read token claims", http.StatusUnauthorized)
		return
	}

	// Because just used jtw.RegisteredClaims, ExpiresAt is a struct.
	// Just call .Time on it to get the standard Go time.Time object.
	expiresAt := claims.ExpiresAt.Time

	// 4. Throw it in the database vault!
	err = h.revokedRepo.RevokeToken(r.Context(), signature, expiresAt)
	if err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Successfully logged out. Token burned."}`))
}

