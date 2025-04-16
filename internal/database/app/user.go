package app

import (
	"Backend/internal/database"
	"Backend/internal/models"
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"log"
	"time"
)

func GetUserByUsernameOrEmail(username string) (*models.User, error) {
	var user models.User
	var userID string
	
	// Use sql.Null types for all nullable fields
	var middleName, institutionName, studentIDVerification sql.NullString
	var twoFAImage, twoFASecret, emailVerificationToken, passwordResetToken sql.NullString
	var dateOfBirth, passwordResetExpires sql.NullTime
	var emailVerified, studentIDVerified, twoFAEnabled sql.NullBool
	
	// Log the query we're about to execute
	log.Printf("Executing GetUserByUsernameOrEmail query for: %s", username)
	
	// Use a simpler query with only the columns we know exist in the database
	query := `SELECT 
		id, username, password, first_name, middle_name, last_name, email, 
		student_id, major, profile_picture, date_of_birth, role_id, created_at, updated_at, 
		year, institution_name, gender, 
		email_verified, email_verification_token, password_reset_token, password_reset_expires, 
		student_id_verified, student_id_verification, 
		twofa_enabled, twofa_image, twofa_secret 
		FROM users WHERE username = $1 OR email = $1`
	
	err := database.DB.QueryRow(context.Background(), query, username).Scan(
		&userID, &user.Username, &user.Password, &user.FirstName, &middleName, &user.LastName, &user.Email,
		&user.StudentID, &user.Major, &user.ProfilePicture, &dateOfBirth, &user.RoleID, &user.CreatedAt,
		&user.UpdatedAt, &user.Year, &institutionName, &user.Gender,
		&emailVerified, &emailVerificationToken, &passwordResetToken, &passwordResetExpires,
		&studentIDVerified, &studentIDVerification,
		&twoFAEnabled, &twoFAImage, &twoFASecret)
	
	if err != nil {
		log.Printf("Error in GetUserByUsernameOrEmail: %v", err)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	
	// Parse UUID
	user.ID, err = uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	
	// Handle nullable fields
	if middleName.Valid {
		user.MiddleName = &middleName.String
	}
	
	if dateOfBirth.Valid {
		user.DateOfBirth = &dateOfBirth.Time
	}
	
	if emailVerified.Valid {
		user.EmailVerified = emailVerified.Bool
	}
	
	if emailVerificationToken.Valid {
		user.EmailVerificationToken = emailVerificationToken.String
	}
	
	if passwordResetToken.Valid {
		user.PasswordResetToken = passwordResetToken.String
	}
	
	if passwordResetExpires.Valid {
		user.PasswordResetExpires = &passwordResetExpires.Time
	}
	
	if studentIDVerified.Valid {
		user.StudentIDVerified = studentIDVerified.Bool
	}
	
	if studentIDVerification.Valid {
		user.StudentIDVerification = &studentIDVerification.String
	}
	
	if institutionName.Valid {
		user.InstitutionName = &institutionName.String
	}
	
	if twoFAEnabled.Valid {
		user.TwoFAEnabled = twoFAEnabled.Bool
	}
	
	if twoFAImage.Valid {
		user.TwoFAImage = &twoFAImage.String
	}
	
	if twoFASecret.Valid {
		user.TwoFASecret = &twoFASecret.String
	}
	
	log.Printf("Successfully retrieved user: %s", user.Username)
	return &user, nil
}

func IsUsernameExists(username string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)"
	var exists bool
	err := database.DB.QueryRow(context.Background(), query, username).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func IsEmailExists(email string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)"
	var exists bool
	err := database.DB.QueryRow(context.Background(), query, email).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	var userID string
	
	// Use sql.Null types for all nullable fields
	var middleName, institutionName, studentIDVerification sql.NullString
	var twoFAImage, twoFASecret, emailVerificationToken, passwordResetToken sql.NullString
	var dateOfBirth, passwordResetExpires sql.NullTime
	var emailVerified, studentIDVerified, twoFAEnabled sql.NullBool
	
	// Log the query we're about to execute
	log.Printf("Executing GetUserByUsername query for: %s", username)
	
	// Use a simpler query with only the columns we know exist in the database
	query := `SELECT 
		id, username, password, first_name, middle_name, last_name, email, 
		student_id, major, profile_picture, date_of_birth, role_id, created_at, updated_at, 
		year, institution_name, gender, 
		email_verified, email_verification_token, password_reset_token, password_reset_expires, 
		student_id_verified, student_id_verification, 
		twofa_enabled, twofa_image, twofa_secret 
		FROM users WHERE username = $1`
	
	err := database.DB.QueryRow(context.Background(), query, username).Scan(
		&userID, &user.Username, &user.Password, &user.FirstName, &middleName, &user.LastName, &user.Email,
		&user.StudentID, &user.Major, &user.ProfilePicture, &dateOfBirth, &user.RoleID, &user.CreatedAt,
		&user.UpdatedAt, &user.Year, &institutionName, &user.Gender,
		&emailVerified, &emailVerificationToken, &passwordResetToken, &passwordResetExpires,
		&studentIDVerified, &studentIDVerification,
		&twoFAEnabled, &twoFAImage, &twoFASecret)
	
	if err != nil {
		log.Printf("Error in GetUserByUsername: %v", err)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // User not found, return nil
		}
		return nil, err // Return the actual error here
	}
	
	// Parse UUID
	user.ID, err = uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	
	// Handle nullable fields
	if middleName.Valid {
		user.MiddleName = &middleName.String
	}
	
	if dateOfBirth.Valid {
		user.DateOfBirth = &dateOfBirth.Time
	}
	
	if emailVerified.Valid {
		user.EmailVerified = emailVerified.Bool
	}
	
	if emailVerificationToken.Valid {
		user.EmailVerificationToken = emailVerificationToken.String
	}
	
	if passwordResetToken.Valid {
		user.PasswordResetToken = passwordResetToken.String
	}
	
	if passwordResetExpires.Valid {
		user.PasswordResetExpires = &passwordResetExpires.Time
	}
	
	if studentIDVerified.Valid {
		user.StudentIDVerified = studentIDVerified.Bool
	}
	
	if studentIDVerification.Valid {
		user.StudentIDVerification = &studentIDVerification.String
	}
	
	if institutionName.Valid {
		user.InstitutionName = &institutionName.String
	}
	
	if twoFAEnabled.Valid {
		user.TwoFAEnabled = twoFAEnabled.Bool
	}
	
	if twoFAImage.Valid {
		user.TwoFAImage = &twoFAImage.String
	}
	
	if twoFASecret.Valid {
		user.TwoFASecret = &twoFASecret.String
	}
	
	log.Printf("Successfully retrieved user by username: %s", user.Username)
	return &user, nil
}

func GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	var userID string
	
	// Use sql.Null types for all nullable fields
	var middleName, institutionName, studentIDVerification sql.NullString
	var twoFAImage, twoFASecret, emailVerificationToken, passwordResetToken sql.NullString
	var dateOfBirth, passwordResetExpires sql.NullTime
	var emailVerified, studentIDVerified, twoFAEnabled sql.NullBool
	
	// Log the query we're about to execute
	log.Printf("Executing GetUserByEmail query for: %s", email)
	
	// Use a simpler query with only the columns we know exist in the database
	query := `SELECT 
		id, username, password, first_name, middle_name, last_name, email, 
		student_id, major, profile_picture, date_of_birth, role_id, created_at, updated_at, 
		year, institution_name, gender, 
		email_verified, email_verification_token, password_reset_token, password_reset_expires, 
		student_id_verified, student_id_verification, 
		twofa_enabled, twofa_image, twofa_secret 
		FROM users WHERE email = $1`
	
	err := database.DB.QueryRow(context.Background(), query, email).Scan(
		&userID, &user.Username, &user.Password, &user.FirstName, &middleName, &user.LastName, &user.Email,
		&user.StudentID, &user.Major, &user.ProfilePicture, &dateOfBirth, &user.RoleID, &user.CreatedAt,
		&user.UpdatedAt, &user.Year, &institutionName, &user.Gender,
		&emailVerified, &emailVerificationToken, &passwordResetToken, &passwordResetExpires,
		&studentIDVerified, &studentIDVerification,
		&twoFAEnabled, &twoFAImage, &twoFASecret)
	
	if err != nil {
		log.Printf("Error in GetUserByEmail: %v", err)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // User not found, return nil
		}
		return nil, err
	}
	
	// Parse UUID
	user.ID, err = uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	
	// Handle nullable fields
	if middleName.Valid {
		user.MiddleName = &middleName.String
	}
	
	if dateOfBirth.Valid {
		user.DateOfBirth = &dateOfBirth.Time
	}
	
	if emailVerified.Valid {
		user.EmailVerified = emailVerified.Bool
	}
	
	if emailVerificationToken.Valid {
		user.EmailVerificationToken = emailVerificationToken.String
	}
	
	if passwordResetToken.Valid {
		user.PasswordResetToken = passwordResetToken.String
	}
	
	if passwordResetExpires.Valid {
		user.PasswordResetExpires = &passwordResetExpires.Time
	}
	
	if studentIDVerified.Valid {
		user.StudentIDVerified = studentIDVerified.Bool
	}
	
	if studentIDVerification.Valid {
		user.StudentIDVerification = &studentIDVerification.String
	}
	
	if institutionName.Valid {
		user.InstitutionName = &institutionName.String
	}
	
	if twoFAEnabled.Valid {
		user.TwoFAEnabled = twoFAEnabled.Bool
	}
	
	if twoFAImage.Valid {
		user.TwoFAImage = &twoFAImage.String
	}
	
	if twoFASecret.Valid {
		user.TwoFASecret = &twoFASecret.String
	}
	
	log.Printf("Successfully retrieved user by email: %s", user.Email)
	return &user, nil
}

func GetUserByID(userID uuid.UUID) (*models.User, error) {
	var user models.User
	
	// Use sql.Null types for all nullable fields
	var middleName, institutionName, studentIDVerification sql.NullString
	var twoFAImage, twoFASecret, emailVerificationToken, passwordResetToken sql.NullString
	var dateOfBirth, passwordResetExpires sql.NullTime
	var emailVerified, studentIDVerified, twoFAEnabled sql.NullBool
	
	// Log the query we're about to execute
	log.Printf("Executing GetUserByID query for ID: %s", userID.String())
	
	// Use a simpler query with only the columns we know exist in the database
	query := `SELECT 
		id, username, password, first_name, middle_name, last_name, email, 
		student_id, major, profile_picture, date_of_birth, role_id, created_at, updated_at, 
		year, institution_name, gender, 
		email_verified, email_verification_token, password_reset_token, password_reset_expires, 
		student_id_verified, student_id_verification, 
		twofa_enabled, twofa_image, twofa_secret 
		FROM users WHERE id = $1`
	
	err := database.DB.QueryRow(context.Background(), query, userID).Scan(
		&user.ID, &user.Username, &user.Password, &user.FirstName, &middleName, &user.LastName, &user.Email,
		&user.StudentID, &user.Major, &user.ProfilePicture, &dateOfBirth, &user.RoleID, &user.CreatedAt,
		&user.UpdatedAt, &user.Year, &institutionName, &user.Gender,
		&emailVerified, &emailVerificationToken, &passwordResetToken, &passwordResetExpires,
		&studentIDVerified, &studentIDVerification,
		&twoFAEnabled, &twoFAImage, &twoFASecret)
	
	if err != nil {
		log.Printf("Error in GetUserByID: %v", err)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	
	// Handle nullable fields
	if middleName.Valid {
		user.MiddleName = &middleName.String
	}
	
	if dateOfBirth.Valid {
		user.DateOfBirth = &dateOfBirth.Time
	}
	
	if emailVerified.Valid {
		user.EmailVerified = emailVerified.Bool
	}
	
	if emailVerificationToken.Valid {
		user.EmailVerificationToken = emailVerificationToken.String
	}
	
	if passwordResetToken.Valid {
		user.PasswordResetToken = passwordResetToken.String
	}
	
	if passwordResetExpires.Valid {
		user.PasswordResetExpires = &passwordResetExpires.Time
	}
	
	if studentIDVerified.Valid {
		user.StudentIDVerified = studentIDVerified.Bool
	}
	
	if studentIDVerification.Valid {
		user.StudentIDVerification = &studentIDVerification.String
	}
	
	if institutionName.Valid {
		user.InstitutionName = &institutionName.String
	}
	
	if twoFAEnabled.Valid {
		user.TwoFAEnabled = twoFAEnabled.Bool
	}
	
	if twoFAImage.Valid {
		user.TwoFAImage = &twoFAImage.String
	}
	
	if twoFASecret.Valid {
		user.TwoFASecret = &twoFASecret.String
	}
	
	log.Printf("Successfully retrieved user by ID: %s", userID.String())
	return &user, nil
}

func GetUserByStudentID(studentID string) (*models.User, error) {
	var user models.User
	var userID string
	err := database.DB.QueryRow(context.Background(), "SELECT * FROM users WHERE student_id = $1", studentID).Scan(
		&user.ID, &user.Username, &user.Password, &user.FirstName, &user.MiddleName, &user.LastName, &user.Email,
		&user.StudentID, &user.Major, &user.ProfilePicture, &user.DateOfBirth, &user.RoleID, &user.CreatedAt,
		&user.UpdatedAt, &user.Year, &user.EmailVerified, &user.EmailVerificationToken, &user.PasswordResetToken,
		&user.PasswordResetExpires, &user.StudentIDVerified, &user.StudentIDVerification, &user.InstitutionName,
		&user.Gender, &user.TwoFAEnabled, &user.TwoFAImage, &user.TwoFASecret,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	user.ID, err = uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetRoleIDByUserID(userID uuid.UUID) (int, error) {
	var roleID int
	err := database.DB.QueryRow(context.Background(), "SELECT role_id FROM users WHERE id = $1", userID).Scan(&roleID)
	if err != nil {
		return 0, err
	}
	return roleID, nil
}

func CheckStudentIDExists(studentID string) (bool, error) {
	var exists bool
	err := database.DB.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM users WHERE student_id = $1)", studentID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func UpdateUser(UserID uuid.UUID, updatedUser *models.User) error {
	_, err := database.DB.Exec(context.Background(), `
		UPDATE users SET username = $1, password = $2, first_name = $3, middle_name = $4, last_name = $5, email = $6,
		student_id = $7, major = $8, year = $9, role_id = $10, updated_at = $11, institution_name= $12, gender = $13, date_of_birth = $14
		WHERE id = $15`,
		updatedUser.Username, updatedUser.Password, updatedUser.FirstName, updatedUser.MiddleName, updatedUser.LastName,
		updatedUser.Email, updatedUser.StudentID, updatedUser.Major, updatedUser.Year, updatedUser.RoleID,
		updatedUser.UpdatedAt, updatedUser.InstitutionName, updatedUser.Gender, updatedUser.DateOfBirth, UserID)
	return err
}

func ChangePassword(userID uuid.UUID, newPassword string) error {
	_, err := database.DB.Exec(context.Background(), "UPDATE users SET password = $1 WHERE id = $2", newPassword, userID)
	return err
}

func SavePasswordResetToken(userID uuid.UUID, token string, expires time.Time) error {
	_, err := database.DB.Exec(context.Background(), "UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3", token, expires, userID)
	return err
}

func ToggleTwoFA(userID uuid.UUID, enable bool) error {
	var err error
	if enable {
		_, err = database.DB.Exec(context.Background(),
			"UPDATE users SET twofa_enabled = $1 WHERE id = $2",
			enable, userID)
	} else {
		_, err = database.DB.Exec(context.Background(),
			"UPDATE users SET twofa_enabled = $1, twofa_image = NULL, twofa_secret = NULL WHERE id = $2",
			enable, userID)
	}
	return err
}

func AdminUpdateRoleAndStudentIDVerified(userID uuid.UUID, roleID int, studentIDVerified bool) error {
	_, err := database.DB.Exec(context.Background(), "UPDATE users SET role_id = $1, student_id_verified = $2 WHERE id = $3", roleID, studentIDVerified, userID)
	return err
}

func DeleteUser(userID uuid.UUID) error {
	_, err := database.DB.Exec(context.Background(), "DELETE FROM users WHERE id = $1", userID)
	return err
}

func ListUsers() ([]models.User, error) {
	var users []models.User

	log.Println("before query")

	// previously, we got a NULL issues. so now, we use a simpler query to avoid that 
	query := `SELECT id, username, password, first_name, last_name, email, student_id, major, 
		profile_picture, role_id, created_at, updated_at, year, gender, email_verified, student_id_verified, twofa_enabled 
		FROM users`

	rows, err := database.DB.Query(context.Background(), query)
	if err != nil {
		log.Println("Error executing query:", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user models.User
		var userID string
		
		log.Println("before scan")
		// just scan for non-nullable fields to avoid that errors
		err := rows.Scan(
			&userID,
			&user.Username,
			&user.Password,
			&user.FirstName,
			&user.LastName,
			&user.Email,
			&user.StudentID,
			&user.Major,
			&user.ProfilePicture,
			&user.RoleID,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.Year,
			&user.Gender,
			&user.EmailVerified,
			&user.StudentIDVerified,
			&user.TwoFAEnabled,
		)
		if err != nil {
			log.Println("Error scanning row:", err)
			return nil, err
		}

		// parse UUID
		user.ID, err = uuid.Parse(userID)
		if err != nil {
			log.Println("Error parsing UUID:", err)
			return nil, err
		}

		log.Println("after scan")
		users = append(users, user)
		log.Println("after append")
	}

	if err = rows.Err(); err != nil {
		log.Println("Error after row iteration:", err)
		return nil, err
	}

	log.Println("after loop")
	log.Printf("Successfully retrieved %d users", len(users))
	return users, nil
}

func GetAllUsersBasic() ([]models.User, error) {
	var users []models.User

	log.Println("Getting all users with basic fields")

	// use a very simple query with only essential fields
	query := `SELECT id, username, first_name, last_name, email, student_id, major, 
		profile_picture, role_id, year, gender, email_verified, student_id_verified 
		FROM users`

	rows, err := database.DB.Query(context.Background(), query)
	if err != nil {
		log.Println("Error executing basic users query:", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user models.User
		var userID string
		
		// again, only scan essential non-nullable fields
		err := rows.Scan(
			&userID,
			&user.Username,
			&user.FirstName,
			&user.LastName,
			&user.Email,
			&user.StudentID,
			&user.Major,
			&user.ProfilePicture,
			&user.RoleID,
			&user.Year,
			&user.Gender,
			&user.EmailVerified,
			&user.StudentIDVerified,
		)
		if err != nil {
			log.Println("Error scanning basic user row:", err)
			continue
		}

		// Parse UUID
		user.ID, err = uuid.Parse(userID)
		if err != nil {
			log.Println("Error parsing UUID:", err)
			continue
		}

		// Set default values for required fields
		user.Password = ""
		user.CreatedAt = time.Now()
		user.UpdatedAt = time.Now()

		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		log.Println("Error after basic users iteration:", err)
		return nil, err
	}

	log.Printf("Successfully retrieved %d basic users", len(users))
	return users, nil
}

func UploadProfilePicture(userID uuid.UUID, profilePicture string) error {
	_, err := database.DB.Exec(context.Background(), "UPDATE users SET profile_picture = $1 WHERE id = $2", profilePicture, userID)
	return err
}

func UploadStudentID(userID uuid.UUID, studentID string) error {
	_, err := database.DB.Exec(context.Background(), "UPDATE users SET student_id_verification = $1 WHERE id = $2", studentID, userID)
	return err
}

func SaveTwoFAInfo(userID uuid.UUID, secret string, image string) error {
	_, err := database.DB.Exec(context.Background(), "UPDATE users SET twofa_image = $1, twofa_secret = $2 WHERE id = $3", image, secret, userID)
	return err
}
