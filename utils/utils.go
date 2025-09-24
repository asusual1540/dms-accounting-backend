package utils

import (
	"dms-accounting/database"
	"dms-accounting/models/user"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"github.com/jinzhu/now"
)

// Mutex for safe concurrent access
var mu sync.Mutex

// Global variable to store decoded token data
var GlobalTokenData map[string]interface{}

// SetTokenData sets the global token data
func SetTokenData(data map[string]interface{}) {
	mu.Lock()
	defer mu.Unlock()
	GlobalTokenData = data
}

// GetTokenData gets the global token data
func GetTokenData() map[string]interface{} {
	mu.Lock()
	defer mu.Unlock()
	return GlobalTokenData
}

// Function to calculate age in Years, Months, and Days
func CalculateAge(dob time.Time) (int, int, int) {
	currentTime := time.Now()

	// Extract year, month, and day
	years := currentTime.Year() - dob.Year()
	months := int(currentTime.Month()) - int(dob.Month())
	days := currentTime.Day() - dob.Day()

	// Adjust for negative months (if birthday hasn't occurred this year)
	if months < 0 {
		years--
		months += 12
	}

	// Adjust for negative days (if birthday day hasn't occurred this month)
	if days < 0 {
		previousMonth := now.With(currentTime).BeginningOfMonth().AddDate(0, 0, -1) // Get last day of the previous month
		days += previousMonth.Day()
		months--
	}

	return years, months, days
}
func ExtractUUIDFromToken(c *fiber.Ctx) (string, error) {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	// Split "Bearer <token>"
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return "", fmt.Errorf("invalid token format")
	}

	tokenString := tokenParts[1]

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method (adjust as per your JWT configuration)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		// Replace with your secret key
		return []byte("your_secret_key"), nil
	})

	if err != nil {
		return "", err
	}

	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		uid, ok := claims["Uid"].(string)
		if !ok {
			return "", fmt.Errorf("uuid not found in token")
		}
		return uid, nil
	}

	return "", fmt.Errorf("invalid token")
}

// GetUserByUUID retrieves a user by their UUID from the database
func GetUserByUUID(uuid string) (*user.User, error) {
	if uuid == "" {
		return nil, errors.New("UUID cannot be empty")
	}

	var userModel user.User
	if err := database.DB.Where("uuid = ?", uuid).First(&userModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &userModel, nil
}

//
