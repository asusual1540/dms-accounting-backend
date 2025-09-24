package middleware

import (
	"dms-accounting/constants"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Permission helper functions to work with existing middleware

// RequirePermissions is a helper function that creates a middleware with specific permissions
func RequirePermissions(permissions ...string) fiber.Handler {
	return IsAuthenticated(permissions)
}

// RequireAnyPermission allows access if user has any of the specified permissions
func RequireAnyPermission(permissions ...string) fiber.Handler {
	// Add "any" to allow flexible permission checking
	allPerms := append(permissions, constants.PermAny)
	return IsAuthenticated(allPerms)
}

// RequireAuthentication only requires valid authentication without specific permissions
func RequireAuthentication() fiber.Handler {
	return IsAuthenticated([]string{constants.PermAny})
}

// CheckPermissionInController checks if user has specific permission within a controller
func CheckPermissionInController(c *fiber.Ctx, requiredPermission string) bool {
	userPermissions, ok := c.Locals("permissions").(map[string]bool)
	if !ok {
		// Fallback to extracting from user claims
		userClaims, ok := c.Locals("user").(jwt.MapClaims)
		if !ok {
			return false
		}
		userPermissions = extractUserPermissionsFromClaims(userClaims)
	}

	return userPermissions[requiredPermission]
}

// GetUserPermissions returns all user permissions from context
func GetUserPermissions(c *fiber.Ctx) map[string]bool {
	userPermissions, ok := c.Locals("permissions").(map[string]bool)
	if !ok {
		// Fallback to extracting from user claims
		userClaims, ok := c.Locals("user").(jwt.MapClaims)
		if !ok {
			return make(map[string]bool)
		}
		return extractUserPermissionsFromClaims(userClaims)
	}
	return userPermissions
}

func extractUserPermissionsFromClaims(claims jwt.MapClaims) map[string]bool {
	permissionSet := make(map[string]bool)

	userPermissions, ok := claims["permissions"].([]interface{})
	if !ok {
		return permissionSet
	}

	for _, p := range userPermissions {
		if perm, ok := p.(string); ok {
			permissionSet[perm] = true
		}
	}

	return permissionSet
}
