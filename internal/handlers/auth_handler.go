package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"Identity_Provider/internal/auth"
	"Identity_Provider/internal/models"
	"Identity_Provider/internal/repository"
)

// AuthHandler holds the dependencies our HTTP routes need.
type AuthHandler struct {
	repo repository.UserRepository
	refrestTokenRepo repository.RefreshTokenRepository
	tokenManager *auth.TokenManager
}

// NewAuthHandler is the constructor. Notice it asks for the Interface, not Postgres!
func NewAuthHandler(repo repository.UserRepository, rtr repository.RefreshTokenRepository,tm *auth.TokenManager) *AuthHandler {
	return &AuthHandler{
		repo: repo,
		refrestTokenRepo: rtr,
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
		http.Error(w, "Email already in use or database error", http.StatusConflict)
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
	rawToken, dbHash, err := auth.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate session", http.StatusInternalServerError)
		return
	}

	// 7. Store the Hash in PostgreSQL (Expires in 7 days)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	newSession := &models.RefreshToken{
		UserID: user.ID,
		TokenHash: dbHash,
		ExpiresAt: expiresAt,
	}

	err = h.refrestTokenRepo.CreateToken(r.Context(), newSession)
	if err != nil {
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