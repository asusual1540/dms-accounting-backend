package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"dms-accounting/types"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// FetchPublicKey fetches the public key from the given URL.
func FetchPublicKey(url string) (*rsa.PublicKey, error) {
	// log.Println("Fetching public key from:", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// log.Println("Raw response body:", string(body))

	// Assume the response contains a JSON object with a "key" field.
	keyResponse := struct {
		Key string `json:"key"`
	}{}

	err = json.Unmarshal(body, &keyResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key response: %w", err)
	}

	// log.Println("Public key fetched:", keyResponse.Key)

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(keyResponse.Key))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// log.Println("PEM block decoded successfully")

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// log.Println("Public key parsed successfully")

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	// log.Println("RSA public key extracted successfully")

	return rsaPubKey, nil
}

// VerifyJWT verifies a JWT token using the fetched RSA public key.
func VerifyJWT(tokenString string) (jwt.MapClaims, error) {
	//log.Println("Verifying JWT token...")
	publicKey := init_jwt()
	if publicKey == nil {
		return nil, fmt.Errorf("failed to get public key")
	}
	// Parse the JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure that the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		//log.Println("JWT signing method is RSA")
		return publicKey, nil
	})

	if err != nil {
		log.Printf("Failed to parse JWT: %v", err)
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Validate the token and return the claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		log.Println("Invalid JWT token")
		return nil, fmt.Errorf("invalid JWT token")
	}
}

func init_jwt() *rsa.PublicKey {

	publicKeyURL := os.Getenv("PUBLIC_KEY_URL")

	// Fetch the public key
	// log.Println("Fetching public key from:", publicKeyURL)
	publicKey, err := FetchPublicKey(publicKeyURL)
	if err != nil {
		//log.Printf("Error fetching public key: %v", err)
		return nil
	}

	return publicKey
}

func hasPermission(jwtToken string, requiredPermissions []string) (map[string]interface{}, bool) {
	//log.Printf("Checking permissions for token. Required permissions: %v", requiredPermissions)

	claims, err := VerifyJWT(jwtToken)
	log.Println("Verifying JWT token...", claims)
	if err != nil {
		log.Printf("JWT verification failed: %v", err)
		return nil, false
	}

	//log.Printf("JWT verified successfully. Claims: %v", claims)

	// If "any" is passed, just verify the token without checking specific permissions
	for _, requiredPerm := range requiredPermissions {
		if requiredPerm == "any" {
			//log.Printf("Found 'any' permission, allowing access")
			return claims, true
		}
	}

	// Extract user permissions from the JWT claims
	userPermissions, ok := claims["permissions"].([]interface{})
	if !ok {
		//log.Printf("No permissions found in claims")
		return claims, false // No permissions found
	}

	//log.Printf("User permissions from JWT: %v", userPermissions)

	// Convert user permissions to a map for quick lookup
	permissionSet := make(map[string]bool)
	for _, p := range userPermissions {
		if perm, ok := p.(string); ok {
			permissionSet[perm] = true
		}
	}

	// Check if the user has any of the required permissions
	for _, requiredPerm := range requiredPermissions {
		if permissionSet[requiredPerm] {
			//log.Printf("Permission '%s' found, allowing access", requiredPerm)
			return claims, true
		}
	}

	//log.Printf("No matching permissions found")
	return claims, false // No matching permissions found
}

func IsAuthenticated(requiredPermissions []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		//log.Printf("IsAuthenticated middleware called with permissions: %v", requiredPermissions)

		authHeader := c.Get("Authorization")
		var token string

		if authHeader != "" {
			//log.Printf("Authorization header received: %s", authHeader)

			// Validate Bearer Token
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				//log.Println("Invalid authorization header format")
				return c.Status(401).JSON(fiber.Map{
					"status": "error",
					"error":  "Invalid authorization header format",
				})
			}
			token = tokenParts[1]
		} else {
			// Try to get token from cookie as fallback
			token = c.Cookies("access")
			if token == "" {
				//log.Println("Authorization header and access cookie missing")
				return c.Status(401).JSON(fiber.Map{
					"status": "error",
					"error":  "Authorization token missing",
				})
			}
			//log.Printf("Token retrieved from cookie")
		}

		jwtToken := token // Extract token from either header or cookie
		tokenPreview := jwtToken
		if len(jwtToken) > 50 {
			tokenPreview = jwtToken[:50] + "..."
		}
		log.Printf("Extracted JWT token: %s", tokenPreview)

		decodedClaims, hasAccess := hasPermission(jwtToken, requiredPermissions)
		if !hasAccess {
			log.Println("Access denied - insufficient permissions")
			return c.Status(403).JSON(fiber.Map{"status": "error", "error": "Insufficient permissions"})
		}

		if decodedClaims["username"] == "" {
			//log.Println("Username missing in claims")
			return c.Status(http.StatusUnauthorized).JSON(types.ApiResponse{Message: "Session expired. Login again.", Status: fiber.StatusBadRequest})
		}

		//log.Println("Authentication successful, proceeding to next handler")
		// Optionally attach claims to context
		c.Locals("user", decodedClaims)

		return c.Next()
	}
}
