package services

import (
	"dms-accounting/constants"
	"dms-accounting/middleware"
	"dms-accounting/types"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type PermissionService struct{}

func NewPermissionService() *PermissionService {
	return &PermissionService{}
}

// CheckPermission checks if the current user has a specific permission
func (ps *PermissionService) CheckPermission(c *fiber.Ctx, permission string) bool {
	return middleware.CheckPermissionInController(c, permission)
}

// CheckAnyPermission checks if the current user has any of the specified permissions
func (ps *PermissionService) CheckAnyPermission(c *fiber.Ctx, permissions ...string) bool {
	userPermissions := middleware.GetUserPermissions(c)

	for _, permission := range permissions {
		if userPermissions[permission] {
			return true
		}
	}
	return false
}

// RequirePermission returns an error response if user doesn't have permission
func (ps *PermissionService) RequirePermission(c *fiber.Ctx, permission string) error {
	if !ps.CheckPermission(c, permission) {
		return c.Status(fiber.StatusForbidden).JSON(types.ApiResponse{
			Message: "Insufficient permissions",
			Status:  fiber.StatusForbidden,
		})
	}
	return nil
}

// RequireAnyPermission returns an error response if user doesn't have any of the permissions
func (ps *PermissionService) RequireAnyPermission(c *fiber.Ctx, permissions ...string) error {
	if !ps.CheckAnyPermission(c, permissions...) {
		return c.Status(fiber.StatusForbidden).JSON(types.ApiResponse{
			Message: "Insufficient permissions",
			Status:  fiber.StatusForbidden,
		})
	}
	return nil
}

// GetUserInfo returns user information from JWT claims
func (ps *PermissionService) GetUserInfo(c *fiber.Ctx) (jwt.MapClaims, bool) {
	userClaims, ok := c.Locals("user").(jwt.MapClaims)
	return userClaims, ok
}

// GetUserID returns user ID from JWT claims
func (ps *PermissionService) GetUserID(c *fiber.Ctx) (string, bool) {
	userClaims, ok := ps.GetUserInfo(c)
	if !ok {
		return "", false
	}

	userID, ok := userClaims["user_id"].(string)
	return userID, ok
}

// GetUsername returns username from JWT claims
func (ps *PermissionService) GetUsername(c *fiber.Ctx) (string, bool) {
	userClaims, ok := ps.GetUserInfo(c)
	if !ok {
		return "", false
	}

	username, ok := userClaims["username"].(string)
	return username, ok
}

// IsAdmin checks if user has admin privileges
func (ps *PermissionService) IsAdmin(c *fiber.Ctx) bool {
	return ps.CheckAnyPermission(c, constants.OrganizationAdminPermissions...)
}

// IsOrgManager checks if user has organization manager privileges
func (ps *PermissionService) IsOrgManager(c *fiber.Ctx) bool {
	return ps.CheckAnyPermission(c, constants.OrganizationManagerPermissions...)
}

// CanDebit checks if user can debit accounts
func (ps *PermissionService) CanDebit(c *fiber.Ctx) bool {
	return ps.CheckAnyPermission(c, constants.OrganizationDebitPermissions...)
}
