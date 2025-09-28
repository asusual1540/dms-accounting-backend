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
		AccountNumber string  `json:"account_number" validate:"required,min=5,max=19"`
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
	if request.Reference == "" || request.Amount <= 0 || request.AccountNumber == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "All fields are required: reference, amount, account_number",
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

	// Validate account number format (5-19 digits)
	if len(request.AccountNumber) < 5 || len(request.AccountNumber) > 19 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Invalid account number format. Must be 5-19 digits",
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
		// Find and lock the target account
		var toAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("account_number = ?", request.AccountNumber).First(&toAccount).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusNotFound, "Account not found with this account number")
			}
			return err
		}

		// Auto-activate and unlock account if needed
		if !toAccount.IsActive || toAccount.IsLocked {
			toAccount.IsActive = true
			toAccount.IsLocked = false
			if err := tx.Save(&toAccount).Error; err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, "Failed to activate/unlock account")
			}
		}

		// Find the AccountOwner record for this account and set admin if not already set
		var accountOwner accountModel.AccountOwner
		if err := tx.Where("account_id = ?", toAccount.ID).First(&accountOwner).Error; err != nil {
			if err != gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusInternalServerError, "Failed to find account owner")
			}
			// If AccountOwner doesn't exist, this is unusual but we'll continue without setting admin
			logger.Warning("AccountOwner record not found for account ID: " + request.AccountNumber)
		} else {
			// Check if admin is not already set for this account
			if accountOwner.AdminID == nil {
				// Set the current admin as the AdminID for this account
				accountOwner.AdminID = &adminID
				if err := tx.Save(&accountOwner).Error; err != nil {
					return fiber.NewError(fiber.StatusInternalServerError, "Failed to set admin for account")
				}
				logger.Info("Admin assigned to account: " + request.AccountNumber)
			}
		}

		// Check if reference already exists (duplicate prevention)
		// var existingLedger accountModel.AccountLedger
		// if err := tx.Where("reference = ? AND credit IS NOT NULL AND is_delete = 0", request.Reference).First(&existingLedger).Error; err == nil {
		// 	return fiber.NewError(fiber.StatusBadRequest, "Reference already exists for a credit transaction")
		// }

		// Check account currency compatibility (assuming BDT for now)
		if toAccount.Currency != "BDT" {
			return fiber.NewError(fiber.StatusBadRequest, "Account currency must be BDT for balance addition")
		}

		// Find or get the admin's account for proper double-entry bookkeeping
		var adminAccount accountModel.Account
		var adminAccountOwner accountModel.AccountOwner
		if err := tx.Where("user_id = ?", adminID).First(&adminAccountOwner).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusBadRequest, "Admin account not found. Admin must have an account to transfer funds.")
			}
			return err
		}

		// Load the admin account details
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", *adminAccountOwner.AccountID).First(&adminAccount).Error; err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to load admin account details")
		}

		// Check if admin account has sufficient balance (optional - uncomment if you want to enforce this)
		// if adminAccount.CurrentBalance < request.Amount {
		//     return fiber.NewError(fiber.StatusBadRequest, "Admin account has insufficient balance")
		// }

		// Create debit ledger entry (money leaving admin account)
		debitLedger := accountModel.AccountLedger{
			BillID:                    nil,
			Reference:                 request.Reference,
			Debit:                     &request.Amount,              // debit from admin account
			FromAccountCurrentBalance: &toAccount.CurrentBalance,    // Store current balance before transaction
			ToAccountCurrentBalance:   &adminAccount.CurrentBalance, // Store current balance before transaction
			IsAutoVerified:            true,
			StatusActive:              1,
			IsDelete:                  0,
			ToAccount:                 adminAccount.ID, // destination account
			FromAccount:               &toAccount.ID,   // source account (admin's account)
			ApprovalStatus:            1,
			ApprovedBy:                &adminID,
			ApprovedAt:                ptrTime(time.Now()),
			VerifiedBy:                &adminID,
			VerifiedAt:                ptrTime(time.Now()),
			TransactionType:           "transfer",
			CreatedAt:                 time.Now(),
			UpdatedAt:                 ptrTime(time.Now()),
		}

		if err := tx.Create(&debitLedger).Error; err != nil {
			return err
		}

		// Create credit ledger entry (money entering account)
		creditLedger := accountModel.AccountLedger{
			BillID:                    nil,
			Reference:                 request.Reference,
			Credit:                    &request.Amount,              // credit to account
			FromAccountCurrentBalance: &adminAccount.CurrentBalance, // Store current balance before transaction
			ToAccountCurrentBalance:   &toAccount.CurrentBalance,    // Store current balance before transaction
			IsAutoVerified:            true,
			StatusActive:              1,
			IsDelete:                  0,
			ToAccount:                 toAccount.ID,     // destination account
			FromAccount:               &adminAccount.ID, // source account (admin's account)
			ApprovalStatus:            1,
			ApprovedBy:                &adminID,
			ApprovedAt:                ptrTime(time.Now()),
			VerifiedBy:                &adminID,
			VerifiedAt:                ptrTime(time.Now()),
			TransactionType:           "transfer",
			CreatedAt:                 time.Now(),
			UpdatedAt:                 ptrTime(time.Now()),
		}

		if err := tx.Create(&creditLedger).Error; err != nil {
			return err
		}
		newLedger = creditLedger // Use credit ledger for response

		// Update admin account balance (subtract the amount)
		adminAccount.CurrentBalance -= request.Amount
		if err := tx.Save(&adminAccount).Error; err != nil {
			return err
		}

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
