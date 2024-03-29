package services

import (
	"Backend/internal/database/app"
	"Backend/internal/models"
	"Backend/pkg/utils"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
)

type AuthService struct{}

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (as *AuthService) RegisterUser(user *models.User) error {
	//hasRows, err := app.TableHasRows("users")
	//if err != nil {
	//	return err
	//}
	//
	//if hasRows {
	//	var checkUsernameOrEmail string
	//	if user.Username != "" {
	//		checkUsernameOrEmail = user.Username
	//	} else {
	//		checkUsernameOrEmail = user.Email
	//	}
	//	existingUsernameOrEmail, err := app.IsUsernameOrEmailExists(checkUsernameOrEmail)
	//	if err != nil {
	//		return err
	//	}
	//
	//	if existingUsernameOrEmail {
	//		return &utils.ConflictError{Message: "Username or email already exists"}
	//	}
	//}

	log.Println("before auth service")
	user.ID = uuid.New()
	user.RoleID = 2

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

	log.Println("after auth service")
	return nil
}

func (as *AuthService) LoginUser(username string, password string) (*models.User, error) {
	user, err := app.AuthenticateUser(username)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, &utils.UnauthorizedError{Message: "invalid credentials"}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		log.Printf("Error comparing hashed password: %v", err)
		return nil, &utils.UnauthorizedError{Message: "invalid credentials"}
	}

	return user, nil
}

func (as *AuthService) IsUsernameOrEmailExists(username string, email string) (bool, error) {
	if username != "" {
		return app.IsUsernameOrEmailExists(username)
	} else {
		return app.IsUsernameOrEmailExists(email)
	}
}

//func (as *AuthService) GetUserByStudentID(studentID string) (*models.User, error) {
//	return app.GetUserByStudentID(studentID)
//}

func (as *AuthService) CheckStudentIDExists(studentID string) (bool, error) {
	return app.CheckStudentIDExists(studentID)
}

func (as *AuthService) CheckUsernameOrEmailExists(username string, email string) (bool, error) {
	if username != "" {
		return app.IsUsernameOrEmailExists(username)
	} else {
		return app.IsUsernameOrEmailExists(email)
	}
}

func (as *AuthService) CheckEmailExists(email string) (bool, error) {
	user, err := app.GetUserByEmail(email)
	if err != nil {
		return false, err
	}

	if user != nil {
		return true, nil
	}

	return false, nil
}
