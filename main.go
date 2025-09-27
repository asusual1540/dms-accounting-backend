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

	var allowlist = map[string]struct{}{
		"https://admin.ekdak.com":   {},
		"https://counter.ekdak.com": {},
		"http://192.168.1.18:3002":  {},
		"http://192.168.1.71:3000":  {},
		"http://192.168.1.76:3000":  {},
		"http://192.168.1.18:3003":  {},
	}
	app.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			_, ok := allowlist[origin]
			return ok
		},
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		ExposeHeaders:    "Content-Length, Authorization",
		AllowCredentials: true,
	}))
	// Use new consolidated routes
	routes.SetupRoutes(app, db)

	app_host := os.Getenv("APP_HOST")
	app_port := os.Getenv("APP_PORT")
	app.Listen(app_host + ":" + app_port)
	// Additional application code can follow...
}
