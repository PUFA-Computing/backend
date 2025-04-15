package utils

import (
	"context"
	"github.com/form3tech-oss/jwt-go"
	"github.com/google/uuid"
	"log"
	"time"
)

func GenerateJWTToken(userID uuid.UUID, secretKey string) (string, error) {
	claims := CustomClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

type CustomClaims struct {
	UserID uuid.UUID `json:"user_id"`
	jwt.StandardClaims
}

func StoreTokenInRedis(userID uuid.UUID, token string) error {
	// If Redis client is nil, just return nil (Redis is disabled)
	if Rdb == nil {
		log.Println("Redis is disabled, skipping token storage")
		return nil
	}
	
	ctx := context.Background()
	ttl := 24 * time.Hour
	err := Rdb.Set(ctx, userID.String(), token, ttl).Err()
	if err != nil {
		log.Printf("Error storing token in Redis: %v", err)
		// Return nil instead of error to allow login without Redis
		return nil
	}

	return nil
}

func RetrieveTokenFromRedis(userID uuid.UUID) (string, error) {
		// If Redis client is nil, return a dummy token (Redis is disabled)
	if Rdb == nil {
		log.Println("Redis is disabled, returning dummy token for validation")
		// Return a non-empty string to allow token validation without Redis
		return "redis-disabled", nil
	}

	ctx := context.Background()
	token, err := Rdb.Get(ctx, userID.String()).Result()
	if err != nil {
		log.Printf("Error retrieving token from Redis: %v", err)
		// Return a dummy token instead of error to allow validation without Redis
		return "redis-disabled", nil
}

	return token, nil
}
