package services

import (
	"Backend/configs"
	"Backend/internal/database"
	"Backend/internal/database/app"
	"Backend/internal/models"
	"Backend/pkg/utils"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type AuthService struct {
	otp *OTPManager
}

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (as *AuthService) RegisterUser(user *models.User) error {
	// Email validation
	if err := as.ValidateEmail(user.Email); err != nil {
		return err
	}

	user.ID = uuid.New()
	user.RoleID = 2
	user.Gender = "male"
	user.ProfilePicture = "https://sg.pufacomputing.live/Assets/male.jpeg"

	// Set major based on studentID
	if user.StudentID[:3] == "001" {
		user.Major = "informatics"
	} else if user.StudentID[:3] == "012" {
		user.Major = "information system"
	} else if user.StudentID[:3] == "013" {
		user.Major = "visual communication design"
	} else if user.StudentID[:3] == "025" {
		user.Major = "interior design"
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashedPassword)

	err = app.CreateUser(user)
	if err != nil {
		return err
	}

	return nil
}

func (as *AuthService) LoginUser(usernameOrEmail string, password string) (*models.User, error) {
	// Log the login attempt with detailed information
	log.Printf("=== LOGIN ATTEMPT START === Username/Email: %s", usernameOrEmail)
	
	// Create a complete user struct with all fields initialized to zero values
	user := &models.User{}
	
	// Use a minimal query to get just the essential fields for authentication
	var userID string
	var hashedPassword string
	
	// Explicitly log the SQL query we're about to execute
	log.Printf("Executing minimal login query for: %s", usernameOrEmail)
	
	// Use a very simple query with only the minimum fields needed for authentication
	query := `SELECT id, username, password, email FROM users WHERE username = $1 OR email = $1`
	
	// Execute the query and scan results into variables
	err := database.DB.QueryRow(context.Background(), query, usernameOrEmail).Scan(
		&userID, &user.Username, &hashedPassword, &user.Email)
	
	// Handle query errors
	if err != nil {
		log.Printf("Login query error: %v", err)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &utils.UnauthorizedError{Message: "invalid credentials"}
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	
	// Log successful query
	log.Printf("Successfully retrieved basic user info for: %s", user.Username)
	
	// Verify password
	log.Printf("Comparing password for user: %s", user.Username)
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		log.Printf("Password verification failed for user %s: %v", user.Username, err)
		return nil, &utils.UnauthorizedError{Message: "invalid credentials"}
	}
	
	// Password verified, parse UUID
	user.ID, err = uuid.Parse(userID)
	if err != nil {
		log.Printf("Error parsing UUID: %v", err)
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}
	
	// Now get additional fields needed for authentication flow
	log.Printf("Fetching additional authentication fields for user: %s", user.Username)
	
	// Only get the specific fields we need for the authentication flow
	var emailVerified, twoFAEnabled sql.NullBool
	
	authQuery := `SELECT email_verified, twofa_enabled FROM users WHERE id = $1`
	err = database.DB.QueryRow(context.Background(), authQuery, userID).Scan(
		&emailVerified, &twoFAEnabled)
	
	if err != nil {
		log.Printf("Warning: Could not fetch auth details: %v - will use defaults", err)
		// Continue with defaults if we can't get these fields
	} else {
		// Set fields only if they're not NULL in the database
		if emailVerified.Valid {
			user.EmailVerified = emailVerified.Bool
		}
		if twoFAEnabled.Valid {
			user.TwoFAEnabled = twoFAEnabled.Bool
		}
		log.Printf("Auth details - EmailVerified: %v, 2FA Enabled: %v", 
			user.EmailVerified, user.TwoFAEnabled)
	}
	
	// Store the hashed password for token generation
	user.Password = hashedPassword
	
	log.Printf("=== LOGIN ATTEMPT SUCCESS === User: %s", user.Username)
	return user, nil
}

func (as *AuthService) IsUsernameExists(username string) (bool, error) {
	return app.IsUsernameExists(username)
}

func (as *AuthService) IsEmailExists(email string) (bool, error) {
	return app.IsEmailExists(email)
}

func (as *AuthService) IsStudentIDExists(studentID string) (bool, error) {
	return app.CheckStudentIDExists(studentID)
}

func (as *AuthService) GetUserByStudentID(studentID string) (*models.User, error) {
	return app.GetUserByStudentID(studentID)
}

func (as *AuthService) GetUserByUsernameOrEmail(usernameOrEmail string) (*models.User, error) {
	return app.AuthenticateUser(usernameOrEmail)
}

func (as *AuthService) CheckStudentIDExists(studentID string) (bool, error) {
	return app.CheckStudentIDExists(studentID)
}

func (as *AuthService) IsEmailVerified(username string) (bool, error) {
	return app.IsEmailVerified(username)
}

func (as *AuthService) IsTokenVerificationEmailExists(token string) (bool, error) {
	return app.IsTokenVerificationEmailExists(token)
}

func (as *AuthService) UpdateEmailVerificationToken(email, token string) error {
	return app.UpdateEmailVerificationToken(email, token)
}

func (as *AuthService) VerifyEmail(token string) error {
	return app.VerifyEmail(token)
}

type HunterEmailVerification struct {
	Data struct {
		Status     string `json:"status"`
		Result     string `json:"result"`
		Score      int    `json:"score"`
		Regexp     bool   `json:"regexp"`
		Gibberish  bool   `json:"gibberish"`
		Disposable bool   `json:"disposable"`
		Webmail    bool   `json:"webmail"`
		MxRecords  bool   `json:"mx_records"`
		SmtpServer bool   `json:"smtp_server"`
		SmtpCheck  bool   `json:"smtp_check"`
		AcceptAll  bool   `json:"accept_all"`
		Block      bool   `json:"block"`
	} `json:"data"`
}

func (as *AuthService) ValidateEmail(email string) error {
	// Always log the email we're validating
	log.Printf("ValidateEmail called for: %s", email)

	// Bypass validation for President University student emails
	if strings.HasSuffix(email, "@student.president.ac.id") {
		log.Println("Bypassing Hunter.io validation for President University student email")
		return nil
	}

	// Load the Hunter API key from the config
	apiKey := configs.LoadConfig().HunterApiKey
	
	// If no API key is provided, bypass validation for development
	if apiKey == "" {
		log.Println("Warning: No Hunter API key provided, bypassing email validation")
		return nil
	}
	
	log.Printf("Validating email %s with Hunter.io", email)
	url := fmt.Sprintf("https://api.hunter.io/v2/email-verifier?email=%s&api_key=%s", email, apiKey)

	// Create a new HTTP client with a timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}(resp.Body)

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to validate email: received status code %d", resp.StatusCode)
	}

	// Parse the JSON response
	var verification HunterEmailVerification
	if err := json.NewDecoder(resp.Body).Decode(&verification); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Check the email status
	switch verification.Data.Status {
	case "valid":
		// Email is valid, proceed with registration
		return nil
	case "invalid":
		return errors.New("the email address is invalid")
	case "disposable":
		return errors.New("the email address is from a disposable email service")
	case "webmail":
		// Optionally handle webmail addresses differently
		return nil
	case "unknown":
		return errors.New("failed to verify the email address")
	default:
		return errors.New("unexpected status from email verification")
	}
}

func (as *AuthService) RequestForgotPassword(userID uuid.UUID) (string, error) {
	tokenOtp := utils.GenerateRandomTokenOtp()
	expiresAt := time.Now().Add(5 * time.Minute)
	otpCode, err := as.otp.GenerateOTP(userID, tokenOtp, time.Minute*5)
	if err != nil {
		return "", err
	}

	// TODO: Send OTP code to email
	log.Println("OTP code:", otpCode)

	err = app.SavePasswordResetToken(userID, tokenOtp, expiresAt)
	if err != nil {
		return "", err
	}

	return otpCode, nil
}

func (as *AuthService) VerifyOTP(userID uuid.UUID, otpCode string) bool {
	tokenOtp, err := app.GetPasswordResetToken(userID)
	if err != nil {
		return false
	}

	return as.otp.VerifyOTP(userID, tokenOtp, otpCode)
}

func (as *AuthService) ResetPassword(userID uuid.UUID, otpCode, password string) (bool, error) {
	tokenOtp, err := app.GetPasswordResetToken(userID)
	if err != nil {
		return false, err
	}

	valid := as.otp.VerifyOTP(userID, tokenOtp, otpCode)
	if !valid {
		return false, nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}

	err = app.UpdatePassword(userID, string(hashedPassword))
	if err != nil {
		return false, err
	}

	return true, nil
}
