package utils

import (
	"context"
	"github.com/redis/go-redis/v9"
	"log"
	"os"
	"time"
)

var Rdb *redis.Client

// RedisEnabled indicates if Redis is available and connected
var RedisEnabled bool = false

func InitRedis() {
	redisURL := os.Getenv("REDIS_URL")
	redisPassword := os.Getenv("REDIS_PASS")

	log.Printf("Redis URL: %s", redisURL)

	// Skip Redis initialization if URL is empty
	if redisURL == "" {
		log.Println("Redis URL not provided. Redis functionality will be disabled.")
		RedisEnabled = false
		return
	}

	options := &redis.Options{
		Addr:     redisURL,
		Password: redisPassword,
		DB:       0,
		DialTimeout: 5 * time.Second,  // Add timeout
	}

	log.Println("Attempting to connect to Redis...")
	Rdb = redis.NewClient(options)
	
	// Use a context with timeout for the ping
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := Rdb.Ping(ctx).Err(); err != nil {
		log.Printf("WARNING: Failed to connect to Redis: %v", err)
		log.Println("Application will continue without Redis. Token revocation will not work.")
		RedisEnabled = false
		return
	}
	
	RedisEnabled = true
	log.Println("Successfully connected to Redis")
}

func IsTokenRevoked(tokenString string) (bool, error) {
	if !RedisEnabled || Rdb == nil {
		// If Redis is not available, assume token is not revoked
		return false, nil
	}
	
	ctx := context.Background()
	exists, err := Rdb.SIsMember(ctx, "revoked_tokens", tokenString).Result()
	if err != nil {
		return false, err
	}

	return exists, nil
}

func RevokeToken(tokenString string) error {
	if !RedisEnabled || Rdb == nil {
		// If Redis is not available, just log and return success
		log.Println("WARNING: Redis not available, token revocation not persisted")
		return nil
	}
	
	ctx := context.Background()
	_, err := Rdb.SAdd(ctx, "revoked_tokens", tokenString).Result()
	if err != nil {
		return err
	}

	return nil
}

func CloseRedis() {
	if !RedisEnabled || Rdb == nil {
		return
	}
	
	err := Rdb.Close()
	if err != nil {
		log.Printf("Error closing Redis connection: %v", err)
		return
	}
	RedisEnabled = false
}
