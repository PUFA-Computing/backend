package main

import (
	"Backend/api"
	"Backend/configs"
	"Backend/internal/database"
	"Backend/pkg/utils"
	"github.com/joho/godotenv"
	"log"
)

func tryInitRedis() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("WARNING: Redis initialization failed: %v", r)
			log.Println("Application will continue without Redis. Token revocation will not work.")
		}
	}()
	
	utils.InitRedis()
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	config := configs.LoadConfig()

	database.Migrate()
	database.Init(config)
	
	// Try to initialize Redis, but continue if it fails
	tryInitRedis()

	r := api.SetupRoutes()

	// port 8080
	port := ":8080"
	if err := r.Run(port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
