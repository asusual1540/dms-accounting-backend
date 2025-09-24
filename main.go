package main

import (
	"dms-accounting/database"
	"dms-accounting/logger"
	"dms-accounting/routes"
	"fmt"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
)

func main() {
	app := fiber.New(fiber.Config{
		ReadBufferSize:  32768, // 32KB read buffer
		WriteBufferSize: 32768, // 32KB write buffer
		ReadTimeout:     time.Second * 30,
		WriteTimeout:    time.Second * 30,
		BodyLimit:       50 * 1024 * 1024, // 50MB body limit
	})
	env := godotenv.Load()
	if env != nil {
		logger.Error("Error loading .env file", env)
		fmt.Println("Error loading .env file", env)
	}
	// Use your custom logger to print a success message.
	logger.Success("Server is running on ip: " + os.Getenv("APP_HOST") + " port: " + os.Getenv("APP_PORT") +
		"\n\t\t\t\t\t\t******************************************************************************************\n")

	// Initialize database with new consolidated db.go
	db, err := database.InitDB()
	if err != nil {
		logger.Error("Failed to connect to the database", err)
		return
	}
	// Initialize the async logger with the database connection
	// go logger.AsyncLogger(db)

	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://192.168.1.76:3000",
		// AllowOrigins:     os.Getenv("FRONTEND_URL") + os.Getenv("EKDAK_FRONTEND_URL"),
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	// Use new consolidated routes
	routes.SetupRoutes(app, db)

	app_host := os.Getenv("APP_HOST")
	app_port := os.Getenv("APP_PORT")
	app.Listen(app_host + ":" + app_port)
	// Additional application code can follow...
}
