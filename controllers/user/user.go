package user

import (
	"dms-accounting/database"
	"dms-accounting/logger"
	"dms-accounting/models/user"
	"dms-accounting/types"
	"dms-accounting/utils"
	"errors"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func GetUserInfo(c *fiber.Ctx) error {
	// Get token data and ensure Uid is available
	tokenData := utils.GetTokenData()
	uid, ok := tokenData["Uid"].(string)
	if !ok {
		response := types.ApiResponse{
			Message: "Invalid token data",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		}
		return c.JSON(&response)
	}

	var user user.User
	if err := database.DB.Where("uid = ?", uid).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("User not found", err)
			response := types.ApiResponse{
				Message: "User not found",
				Status:  fiber.StatusNotFound,
				Data:    nil,
			}
			return c.JSON(&response)
		}
		logger.Error("Error fetching user", err)
		response := types.ApiResponse{
			Message: "Error fetching user",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.JSON(&response)
	}

	// Construct user info response
	userInfo := map[string]interface{}{
		"uid":            user.Uuid,
		"username":       user.Username,
		"legal_name":     user.LegalName,
		"phone_verified": user.PhoneVerified,
		"email_verified": user.EmailVerified,
		"avatar":         user.Avatar,
		"nonce":          user.Nonce,
		"created_by":     user.CreatedByID,
		"approved_by":    user.ApprovedByID,
		"permissions":    user.Permissions,
		"created_at":     user.CreatedAt.Format("2006-01-02 15:04:05"),
		"updated_at":     user.UpdatedAt.Format("2006-01-02 15:04:05"),
	}

	// Send successful response
	response := types.ApiResponse{
		Message: "User fetched successfully",
		Status:  fiber.StatusOK,
		Data:    userInfo,
	}
	logger.Success("User fetched successfully")
	return c.JSON(&response)
}
