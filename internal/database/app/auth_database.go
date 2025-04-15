package app

import (
	"Backend/internal/database"
	"Backend/internal/models"
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"log"
)

func CreateUser(user *models.User) error {

	query := `
		INSERT INTO users (id, username, password, first_name, middle_name, last_name, email, student_id, major, year, role_id, email_verification_token, institution_name, gender)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err := database.DB.Exec(
		context.Background(),
		query,
		user.ID, user.Username, user.Password, user.FirstName, user.MiddleName, user.LastName, user.Email,
		user.StudentID, user.Major, user.Year, user.RoleID, user.EmailVerificationToken, user.InstitutionName, user.Gender,
	)
	if err != nil {
		log.Printf("Error during query execution or scanning: %v", err)
		return err
	}
	return nil
}

func AuthenticateUser(usernameOrEmail string) (*models.User, error) {
	// Use an absolute minimal query with only the essential fields needed for authentication
	query := `
		SELECT id, username, password
		FROM users
		WHERE username = $1 OR email = $1`

	log.Printf("Executing minimal login query for user: %s", usernameOrEmail)
	
	// Create a minimal user object with just the fields needed for authentication
	var user models.User
	var userIDString string
	
	err := database.DB.QueryRow(
		context.Background(),
		query,
		usernameOrEmail,
	).Scan(
		&userIDString,
		&user.Username,
		&user.Password,
	)

	if errors.Is(err, sql.ErrNoRows) {
		log.Println("No user found with username or email:", usernameOrEmail)
		return nil, err
	} else if err != nil {
		log.Println("Error during query execution or scanning:", err)
		return nil, err
	}

	// Parse the UUID
	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return nil, err
	}
	
	user.ID = userID
	
	// Set default values for fields that might be needed but aren't critical for login
	user.FirstName = ""
	user.LastName = ""
	user.Email = usernameOrEmail
	user.StudentID = ""
	user.Major = ""
	user.Year = ""
	user.Gender = ""
	user.ProfilePicture = ""
	user.EmailVerificationToken = ""
	user.PasswordResetToken = ""
	user.EmailVerified = false
	user.TwoFAEnabled = false
	
	// Now fetch additional user details if needed
	detailsQuery := `
		SELECT email, email_verified, twofa_enabled
		FROM users
		WHERE id = $1`
	
	err = database.DB.QueryRow(
		context.Background(),
		detailsQuery,
		userID,
	).Scan(
		&user.Email,
		&user.EmailVerified,
		&user.TwoFAEnabled,
	)
	
	if err != nil {
		log.Printf("Warning: Could not fetch additional user details: %v", err)
		// Continue anyway, as we have the essential fields for authentication
	}
	
	return &user, nil
}

func IsEmailVerified(email string) (bool, error) {
	var verified bool
	query := `
		SELECT email_verified
		FROM users
		WHERE email = $1 OR username = $1`
	err := database.DB.QueryRow(
		context.Background(),
		query,
		email,
	).Scan(&verified)
	if err != nil {
		log.Printf("Error during query execution or scanning: %v", err)
		return false, err
	}
	return verified, nil
}

func IsTokenVerificationEmailExists(token string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE email_verification_token = $1
		)`
	err := database.DB.QueryRow(
		context.Background(),
		query,
		token,
	).Scan(&exists)
	if err != nil {
		log.Printf("Error during query execution or scanning: %v", err)
		return false, err
	}
	return exists, nil
}

func UpdateEmailVerificationToken(email, token string) error {
	query := `
		UPDATE users
		SET email_verification_token = $1
		WHERE email = $2`
	_, err := database.DB.Exec(
		context.Background(),
		query,
		token,
		email,
	)
	if err != nil {
		log.Printf("Error during query execution or scanning: %v", err)
		return err
	}
	return nil

}

// VerifyEmail updates the email_verified field in the users table and return error if verification token is invalid
func VerifyEmail(token string) error {
	query := `
		UPDATE users
		SET email_verified = TRUE
		WHERE email_verification_token = $1`
	_, err := database.DB.Exec(
		context.Background(),
		query,
		token,
	)
	if err != nil {
		log.Printf("Error during query execution or scanning: %v", err)
		return err
	}
	return nil
}

func GetPasswordResetToken(userID uuid.UUID) (string, error) {
	var token string
	query := `
		SELECT password_reset_token
		FROM users
		WHERE id = $1`
	err := database.DB.QueryRow(
		context.Background(),
		query,
		userID,
	).Scan(&token)
	if err != nil {
		log.Printf("Error during query execution or scanning: %v", err)
		return "", err
	}
	return token, nil
}

func UpdatePassword(userID uuid.UUID, newPassword string) error {
	query := `
		UPDATE users
		SET password = $1
		WHERE id = $2`
	_, err := database.DB.Exec(
		context.Background(),
		query,
		newPassword,
		userID,
	)
	if err != nil {
		log.Printf("Error during query execution or scanning: %v", err)
		return err
	}
	return nil
}
