package account

import (
	"dms-accounting/database"
	"dms-accounting/logger"
	accountModel "dms-accounting/models/account"
	"dms-accounting/models/user"
	"dms-accounting/types"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AdminBalanceController handles admin operations for managing user balances
type AdminBalanceController struct {
	db             *gorm.DB
	loggerInstance *logger.AsyncLogger
}

// NewAdminBalanceController creates a new admin balance controller
func NewAdminBalanceController(db *gorm.DB, loggerInstance *logger.AsyncLogger) *AdminBalanceController {
	return &AdminBalanceController{db: db, loggerInstance: loggerInstance}
}

// AddBalance allows admin to add balance to any user's account
func (a *AdminBalanceController) AddBalance(c *fiber.Ctx) error {
	// Parse JSON request body
	var request struct {
		Reference     string  `json:"reference" validate:"required,min=3,max=255"`
		Amount        float64 `json:"amount" validate:"required,gt=0,lte=1000000"`
		AccountNumber string  `json:"account_number" validate:"required,len=19"`
		RecipientID   uint    `json:"recipient_id" validate:"required,gt=0"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Invalid JSON format",
			"data":        []interface{}{},
		})
	}

	// Validate required fields
	if request.Reference == "" || request.Amount <= 0 || request.AccountNumber == "" || request.RecipientID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "All fields are required: reference, amount, account_number, recipient_id",
			"data":        []interface{}{},
		})
	}

	// Validate reference length
	if len(request.Reference) < 3 || len(request.Reference) > 255 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Reference must be between 3 and 255 characters",
			"data":        []interface{}{},
		})
	}

	// Validate account number format (19 digits)
	if len(request.AccountNumber) != 19 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Invalid account number format. Must be 19 digits",
			"data":        []interface{}{},
		})
	}

	// Validate amount range (max 1,000,000 BDT for safety)
	if request.Amount > 1000000 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Amount cannot exceed 1,000,000 BDT",
			"data":        []interface{}{},
		})
	}

	// Get current admin user from context
	adminInfo := c.Locals("user").(map[string]interface{})
	adminUUID, ok := adminInfo["uuid"].(string)
	if !ok || adminUUID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 401,
			"message":     "Invalid admin session - UUID not found",
			"data":        []interface{}{},
		})
	}

	// Find admin by UUID to get the admin ID
	var currentAdmin user.User
	if err := database.DB.Where("uuid = ?", adminUUID).First(&currentAdmin).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 401,
			"message":     "Admin not found in database",
			"data":        []interface{}{},
		})
	}
	adminID := currentAdmin.ID

	// Start DB transaction
	var newLedger accountModel.AccountLedger

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// Verify recipient exists
		var recipient user.User
		if err := tx.Where("id = ?", request.RecipientID).First(&recipient).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusNotFound, "Recipient user not found")
			}
			return err
		}

		// Find and lock the target account
		var toAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("account_number = ?", request.AccountNumber).First(&toAccount).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusNotFound, "Account not found with this account number")
			}
			return err
		}

		// Check if account is active
		if !toAccount.IsActive || toAccount.IsLocked {
			return fiber.NewError(fiber.StatusBadRequest, "Account is not active or is locked")
		}

		// Check if reference already exists (duplicate prevention)
		var existingLedger accountModel.AccountLedger
		if err := tx.Where("reference = ? AND credit IS NOT NULL AND is_delete = 0", request.Reference).First(&existingLedger).Error; err == nil {
			return fiber.NewError(fiber.StatusBadRequest, "Reference already exists for a credit transaction")
		}

		// Check account currency compatibility (assuming BDT for now)
		if toAccount.Currency != "BDT" {
			return fiber.NewError(fiber.StatusBadRequest, "Account currency must be BDT for balance addition")
		}

		// Verify that the recipient owns this account or is associated with it
		var userAccount accountModel.UserAccount
		if err := tx.Where("user_id = ? AND account_id = ? AND is_active = ? AND is_delete = ?",
			request.RecipientID, toAccount.ID, true, false).First(&userAccount).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusBadRequest, "Account does not belong to the specified recipient")
			}
			return err
		}

		// Create ledger entry for admin balance addition
		ledger := accountModel.AccountLedger{
			BillID:         nil, // No bill for admin balance addition
			RecipientID:    request.RecipientID,
			SenderID:       adminID, // admin who is adding the balance
			OrganizationID: nil,     // No organization for admin balance addition
			Reference:      request.Reference,
			Credit:         &request.Amount,
			IsAutoVerified: true,
			StatusActive:   1,
			IsDelete:       0,
			ToAccount:      &toAccount.ID,
			FromAccount:    &toAccount.ID, // same account for balance addition
			ApprovalStatus: 1,             // auto approved by admin
			ApprovedBy:     &adminID,
			ApprovedAt:     ptrTime(time.Now()),
			VerifiedBy:     &adminID,
			VerifiedAt:     ptrTime(time.Now()),
			CreatedAt:      time.Now(),
			UpdatedAt:      ptrTime(time.Now()),
		}

		if err := tx.Create(&ledger).Error; err != nil {
			return err
		}
		newLedger = ledger

		// Update account balance
		newBalance := toAccount.CurrentBalance + request.Amount

		// Check if new balance would exceed max limit (if set)
		if toAccount.MaxLimit > 0 && newBalance > toAccount.MaxLimit {
			return fiber.NewError(fiber.StatusBadRequest, "Credit would exceed account maximum limit")
		}

		toAccount.CurrentBalance = newBalance
		if err := tx.Save(&toAccount).Error; err != nil {
			return err
		}

		return nil
	})

	// Handle transaction errors
	if err != nil {
		if fiberErr, ok := err.(*fiber.Error); ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":      "failed",
				"status_code": fiberErr.Code,
				"message":     fiberErr.Message,
				"data":        []interface{}{},
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 500,
			"message":     "Transaction failed",
			"data":        []interface{}{},
		})
	}

	// Log the transaction for audit
	a.loggerInstance.Log(types.LogEntry{
		Method:     "POST",
		URL:        c.OriginalURL(),
		StatusCode: 201,
		CreatedAt:  time.Now(),
	})

	// Prepare response data
	responseData := fiber.Map{
		"ledger_id":        newLedger.ID,
		"amount":           request.Amount,
		"reference":        request.Reference,
		"account_number":   request.AccountNumber,
		"recipient_id":     request.RecipientID,
		"admin_id":         adminID,
		"transaction_time": newLedger.CreatedAt,
	}

	// Return success response
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":      "success",
		"status_code": 201,
		"message":     "Balance added successfully to user account",
		"data":        []fiber.Map{responseData},
	})
}
