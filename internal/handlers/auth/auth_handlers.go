package auth

import (
	"Backend/internal/models"
	"Backend/internal/services"
	"Backend/pkg/utils"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
)

type Handlers struct {
	AuthService       *services.AuthService
	PermissionService *services.PermissionService
	EmailService      *services.TestMailService
	UserService       *services.UserService
}

func NewAuthHandlers(authService *services.AuthService, permissionService *services.PermissionService, EmailService *services.TestMailService, userService *services.UserService) *Handlers {
	return &Handlers{
		AuthService:       authService,
		PermissionService: permissionService,
		EmailService:      EmailService,
		UserService:       userService,
	}
}

func (h *Handlers) RegisterUser(c *gin.Context) {
	log.Println("=== Starting RegisterUser function ===")
	var newUser models.User
	suffix := "@student.president.ac.id"

	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	// Remove whitespace from firstname and lastname
	newUser.FirstName = utils.RemoveWhitespace(newUser.FirstName)
	newUser.LastName = utils.RemoveWhitespace(newUser.LastName)
	newUser.Username = utils.RemoveWhitespace(newUser.Username)

	// Check if username or email already exists
	// // if username exists add something to username because its generate from firstname and lastname
	if exists, err := h.AuthService.IsUsernameExists(newUser.Username); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	} else if exists {
		// Generate a random string of characters
		randomBytes := make([]byte, 4) // Adjust length as needed
		if _, err := rand.Read(randomBytes); err != nil {
			// Handle error if random generation fails
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{"Failed to generate random string"}})
			return
		}
		randomString := base64.URLEncoding.EncodeToString(randomBytes)
		randomString = randomString[0:4] // Keep only the first 4 characters

		// Append the random string to the username
		newUser.Username = fmt.Sprintf("%s%s", newUser.Username, randomString)
		log.Println("New Username: ", newUser.Username)
	}

	log.Printf("Validating email: %s against suffix: %s", newUser.Email, suffix)
	if err := validateEmail(newUser.Email, suffix); err != nil {
		log.Printf("Email validation failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}
	log.Println("Email validation passed")

	if exists, err := h.AuthService.IsEmailExists(newUser.Email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	} else if exists {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{"Email already exists"}})
		return
	}

	if err := validateStudentID(newUser.StudentID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	// Check student ID exists
	if exists, err := h.AuthService.IsStudentIDExists(newUser.StudentID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	} else if exists {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{"Student ID already exists"}})
		return
	}

	// Email Verification Token
	token := utils.GenerateRandomString(32)
	newUser.EmailVerificationToken = token

	if err := h.AuthService.RegisterUser(&newUser); err != nil {
		// Check if it's a validation error (which should be a 400) or a server error (500)
		if strings.Contains(err.Error(), "email") || 
		   strings.Contains(err.Error(), "invalid") || 
		   strings.Contains(err.Error(), "disposable") || 
		   strings.Contains(err.Error(), "verify") || 
		   strings.Contains(err.Error(), "validation") {
			// This is likely a validation error, return 400 Bad Request
			log.Printf("Email validation error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		} else {
			// This is some other server error, return 500 Internal Server Error
			log.Printf("Server error during registration: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		}
		return
	}

	// Send verification email
	log.Printf("Sending verification email to: %s", newUser.Email)
	if err := h.EmailService.SendVerificationEmail(newUser.Email, token, newUser.ID); err != nil {
		log.Printf("Failed to send verification email: %v", err)
		// Continue with registration even if email sending fails
		log.Println("Continuing with registration despite email sending failure")
	} else {
		log.Println("Verification email sent successfully")
	}

	log.Println("Registration process completed successfully")
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "User Created Successfully",
	})
}

// Validate student ID
func validateStudentID(studentID string) error {
	if len(studentID) != 12 {
		return errors.New("student ID must be 12 characters long")
	} else if studentID[:3] != "001" && studentID[:3] != "012" && studentID[:3] != "013" && studentID[:3] != "025" {
		return errors.New("you are not a student of faculty of computing")
	} else if studentID[3:7] < "2010" {
		return errors.New("you are not eligible to register an account")
	}
	return nil
}

func validateEmail(email, suffix string) error {
	if len(email) < len(suffix) || email[len(email)-len(suffix):] != suffix {
		return errors.New("email must be a President University student email")
	}
	return nil
}

func (h *Handlers) Login(c *gin.Context) {
	var loginRequest struct {
		Username string  `json:"username"`
		Password string  `json:"password"`
		Passcode *string `json:"passcode"`
	}

	if err := c.BindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	// Lowercase the username
	loginRequest.Username = strings.ToLower(loginRequest.Username)

	// Add debug logging
	log.Printf("Attempting login for user: %s", loginRequest.Username)
	user, err := h.AuthService.LoginUser(loginRequest.Username, loginRequest.Password)
	if err != nil {
		// Log the actual error for debugging
		log.Printf("Login error: %v", err)
		
		// Check if it's an unauthorized error or another type of error
		var unauthorizedErr *utils.UnauthorizedError
		if errors.As(err, &unauthorizedErr) {
			// This is an invalid credentials error
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Invalid Credentials"})
		} else {
			// This is a server error
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Login Failed", "error": err.Error()})
		}
		return
	}

	// If there is no passcode, but 2FA is enabled, return otp required
	if loginRequest.Passcode == nil {

		if user.TwoFAEnabled {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Two Factor Authentication Required"})
			return
		}
	}

	if loginRequest.Passcode != nil {
		if !user.TwoFAEnabled {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "2FA is not enabled for this account"})
			return
		}

		_, err := h.UserService.VerifyTwoFA(user.ID, *loginRequest.Passcode)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid 2FA Code"})
			return
		}

	}

	// No need to validate email during login as it was already validated during registration

	// Check isEmailVerified
	isEmailVerified, err := h.AuthService.IsEmailVerified(loginRequest.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Verification Email Sent, Check Your Email"})
		return
	}

	if !isEmailVerified {
		// Send verification email
		user, err := h.AuthService.GetUserByUsernameOrEmail(loginRequest.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
			return
		}

		if user == nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{"User not found"}})
			return
		}

		token := utils.GenerateRandomString(32)

		if err := h.AuthService.UpdateEmailVerificationToken(user.Email, token); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
			return
		}

		if err := h.EmailService.SendVerificationEmail(user.Email, token, user.ID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Email not verified, verification email sent"})
		return
	}

	token, err := utils.GenerateJWTToken(user.ID, os.Getenv("JWT_SECRET_KEY"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	// Try to store token in Redis, but continue even if it fails
	_ = utils.StoreTokenInRedis(user.ID, token)
	// No need to check for errors since we've made Redis optional

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Login Successful",
		"data":    gin.H{"access_token": token, "token_type": "Bearer", "user_id": user.ID.String()},
	})
}

func (h *Handlers) Logout(c *gin.Context) {
	tokenString, err := utils.ExtractTokenFromHeader(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": []string{"Unauthorized"}})
		return
	}

	_, err = utils.ValidateToken(tokenString, os.Getenv("JWT_SECRET_KEY"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": []string{"Unauthorized"}})
		return
	}

	err = utils.RevokeToken(tokenString)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Logout Successful"})
}

func (h *Handlers) RefreshToken(c *gin.Context) {
	tokenString, err := utils.ExtractTokenFromHeader(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": []string{"Unauthorized"}})
		return
	}

	claims, err := utils.ValidateToken(tokenString, os.Getenv("JWT_SECRET_KEY"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": []string{"Unauthorized"}})
		return
	}

	userID := claims.UserID
	token, err := utils.GenerateJWTToken(userID, os.Getenv("JWT_SECRET_KEY"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	if err := utils.StoreTokenInRedis(userID, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Access Token Refreshed Successfully",
		"data": gin.H{
			"access_token": token,
			"token_type":   "Bearer",
			"user_id":      userID.String(),
		},
	})
}

func (h *Handlers) ExtractUserIDAndCheckPermission(c *gin.Context, permissionType string) (uuid.UUID, error) {
	token, err := utils.ExtractTokenFromHeader(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return uuid.UUID{}, err
	}

	userID, err := utils.GetUserIDFromToken(token, os.Getenv("JWT_SECRET_KEY"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return uuid.UUID{}, err
	}

	hasPermission, err := (&services.PermissionService{}).CheckPermission(context.Background(), userID, permissionType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return uuid.UUID{}, err
	}

	if !hasPermission {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": []string{"Unauthorized"}})
		return uuid.UUID{}, err
	}

	return userID, nil
}

func (h *Handlers) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{"Token is required"}})
		return
	}

	exists, err := h.AuthService.IsTokenVerificationEmailExists(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{"Invalid Token"}})
		return
	}

	if err := h.AuthService.VerifyEmail(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Email Verified Successfully"})
}

func (h *Handlers) RequestPasswordReset(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	user, err := h.AuthService.GetUserByUsernameOrEmail(request.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	if user == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{"User not found"}})
		return
	}

	otpCode, err := h.AuthService.RequestForgotPassword(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	if err := h.EmailService.SendOTPEmail(user.Email, otpCode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Password Reset Email Sent"})
}

func (h *Handlers) ResetPassword(c *gin.Context) {
	var request struct {
		Email    string  `json:"email"`
		OTP      string  `json:"otp"`
		Password *string `json:"password"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	user, err := h.AuthService.GetUserByUsernameOrEmail(request.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
		return
	}

	if user == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": []string{"User not found"}})
		return
	}

	// Check if the OTP is valid
	valid := h.AuthService.VerifyOTP(user.ID, request.OTP)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid OTP"})
		return
	}

	// If password is provided, reset it
	if request.Password != nil {
		success, err := h.AuthService.ResetPassword(user.ID, request.OTP, *request.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": []string{err.Error()}})
			return
		}
		if !success {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid OTP"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Password reset successfully"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Valid OTP"})
}
