package domain

type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"-"`
	Role      string `json:"role"`
	NIM       string `json:"nim"`
	Year      string `json:"year"`
}