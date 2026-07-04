package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"Identity_Provider/internal/auth"
	"Identity_Provider/internal/handlers"
	"Identity_Provider/internal/repository"

	_ "github.com/lib/pq"
	"github.com/joho/godotenv"
)

func main() {
	// 0. Load the .env file into the system before doing anything else
	err := godotenv.Load()
	if err != nil {
		log.Fatal("CRITICAL: Error loading .env file")
	}
	
	// 1. Initialize Database (Phase 2)
	connStr := os.Getenv("CONNECTION_STRING_DB")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("CRITICAL: Invalid DB connection string: %v", err)
	}

	// FORCE GO TO PING THE DATABASE
	err = db.Ping()
	if err != nil {
		log.Fatalf("CRITICAL: Cannot connect to PostgreSQL: %v", err)
	}

	// Set the absolute maximum number of simultaneous open connections 
	db.SetMaxOpenConns(25)
	
	// Set the maximum number of connections to leave open and idle in the background
	db.SetMaxIdleConns(25)
	
	// Force connections to close and recycle after 15 minutes to prevent stale TCP drops
	db.SetConnMaxLifetime(15 * time.Minute)
	
	log.Println("✅ Database connection established successfully!")
	// Initialize Repositories
	userRepo := repository.NewPostgresUserRepository(db)
	refreshRepo := repository.NewPostgresRefreshTokenRepository(db)

	// Initialize the Denylist Repository
	revokedRepo := repository.NewPostgresRevokedTokenRepository(db)

	// 2. Initialize Cryptography (Phase 1)
	// (In production, you load these from secure .pem files)
	privPath := os.Getenv("RSA_PRIVATE_KEY_PATH")
	pubPath := os.Getenv("RSA_PUBLIC_KEY_PATH")

	// Fallback to local files if the environment variables aren't set
	if privPath == "" { privPath = "./private.pem" }
	if pubPath == "" { pubPath = "./public.pem" }
	privateKey, publicKey, err := auth.LoadRSAKeys(privPath, pubPath)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to load RSA keys: %v", err)
	}
	tokenManager := auth.NewTokenManager(privateKey, publicKey, "Faisal-IdP")

	// 3. Initialize Controllers (Phase 3)
	authHandler := handlers.NewAuthHandler(userRepo, refreshRepo, revokedRepo, tokenManager)

	// 4. Initialize Router
	mux := http.NewServeMux()

	// ------------------------------------------------
	// PUBLIC ROUTES (No middleware)
	// ------------------------------------------------
	mux.HandleFunc("/api/register", authHandler.Register)
	mux.HandleFunc("/api/login", authHandler.Login)
	mux.HandleFunc("/api/refresh", authHandler.Refresh)

	// ------------------------------------------------
	// PROTECTED ROUTES (Wrapped in RequireAuth)
	// ------------------------------------------------

	// 1. Profile Route
	profileRoute := http.HandlerFunc(handlers.ProfileHandler)
	mux.Handle("/api/profile", handlers.RequireAuth(tokenManager, revokedRepo)(profileRoute))

	// 2. Logout Route (The Kill switch)
	logoutRoute := http.HandlerFunc(authHandler.Logout)
	mux.Handle("/api/logout", handlers.RequireAuth(tokenManager, revokedRepo)(logoutRoute))

	// 3. route ONLY an Admin can access
	adminRoute := http.HandlerFunc(handlers.AdminDashBoardHandler)
	// Notice the chain: RequireAuth -> RequireRole("admin") -> AdminHandler
	mux.Handle("/api/admin", handlers.RequireAuth(tokenManager, revokedRepo)(handlers.RequireRole("admin")(adminRoute),
	),
)

// 5. Start the Server
fmt.Println("Starting the API on port 8080...")
http.ListenAndServe(":8080", mux)
}