package configs

import (
	"fmt"
	"os"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	RedisURL  string
	RedisPass string

	ApiPort      string
	JWTSecretKey string

	CloudflareAccountId   string
	CloudflareR2AccessId  string
	CloudflareR2AccessKey string

	AWSAccessKeyId     string
	AWSSecretAccessKey string
	AWSRegion          string
	S3Bucket           string

	SMTPHost      string
	SMTPPort      string
	SMTPUsername  string
	SMTPPassword  string
	SenderEmail   string

	GithubAccessToken string
	HunterApiKey      string

	BaseURL string
}

func LoadConfig() *Config {
	env := os.Getenv("ENV")

	var baseURl string
	if env == "production" {
		baseURl = "https://computing.president.ac.id"
	} else if env == "staging" {
		baseURl = "http://localhost:3000"
	} else {
		baseURl = "http://localhost:3000"
	}

	cfg := &Config{
		DBHost:                os.Getenv("DB_HOST"),
		DBPort:                os.Getenv("DB_PORT"),
		DBUser:                os.Getenv("DB_USER"),
		DBPassword:            os.Getenv("DB_PASSWORD"),
		DBName:                os.Getenv("DB_NAME"),
		RedisURL:              os.Getenv("REDIS_URL"),
		RedisPass:             os.Getenv("REDIS_PASS"),
		ApiPort:               os.Getenv("API_PORT"),
		JWTSecretKey:          os.Getenv("JWT_SECRET_KEY"),
		CloudflareAccountId:   os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		CloudflareR2AccessId:  os.Getenv("CLOUDFLARE_R2_ACCESS_ID"),
		CloudflareR2AccessKey: os.Getenv("CLOUDFLARE_R2_ACCESS_KEY"),
		AWSAccessKeyId:        os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:    os.Getenv("AWS_SECRET_ACCESS_KEY"),
		AWSRegion:             os.Getenv("AWS_REGION"),
		S3Bucket:              os.Getenv("S3_BUCKET"),
		SMTPHost:         os.Getenv("SMTP_HOST"),
		SMTPPort:         os.Getenv("SMTP_PORT"),
		SMTPUsername:     os.Getenv("SMTP_USERNAME"),
		SMTPPassword:     os.Getenv("SMTP_PASSWORD"),
		SenderEmail:      os.Getenv("SENDER_EMAIL"),
		BaseURL:               baseURl,
		GithubAccessToken:     os.Getenv("GH_ACCESS_TOKEN"),
		HunterApiKey:          os.Getenv("HUNTER_API_KEY"),
	}

	fmt.Printf("Loaded Config: %+v\n", cfg)
	return cfg
}
