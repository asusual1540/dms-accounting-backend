package account

import (
	"bytes"
	"dms-accounting/database"
	"dms-accounting/logger"
	accountModel "dms-accounting/models/account"
	"dms-accounting/models/organization"
	"dms-accounting/models/user"
	"dms-accounting/types/account"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm/clause"

	"gorm.io/gorm"
)

type AccountController struct {
	db             *gorm.DB
	loggerInstance *logger.AsyncLogger
}

func NewAccountController(db *gorm.DB, loggerInstance *logger.AsyncLogger) *AccountController {
	return &AccountController{db: db, loggerInstance: loggerInstance}
}

func (a *AccountController) CreateAccount(c *fiber.Ctx) error {
	var req account.AccountCreateRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
	}

	if req.UserUUID == "" || req.Currency == "" || req.BalanceType == "" || req.AccountType == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "All fields are required",
		})
	}

	var createdAccount accountModel.Account

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// Fetch organization
		var existingOrg organization.Organization
		if err := tx.Where("id = ?", req.OrganizationID).First(&existingOrg).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusBadRequest, "Organization not found")
			}
			return err
		}

		// Fetch user
		var existingUser user.User
		if err := tx.Where("uuid = ?", req.UserUUID).First(&existingUser).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusBadRequest, "User not found")
			}
			return err
		}

		// Check if account already exists for this user in the org
		var existingAccount accountModel.OrganizationAccount
		if err := tx.Where("organization_id = ?", existingOrg.ID).
			First(&existingAccount).Error; err == nil {
			return fiber.NewError(fiber.StatusBadRequest, "Account already exists for this user in this organization")
		} else if err != gorm.ErrRecordNotFound {
			return err
		}

		now := time.Now()
		account := accountModel.Account{
			Currency:      req.Currency,
			AccountType:   req.AccountType,
			MaxLimit:      req.MaxLimit,
			BalanceType:   req.BalanceType,
			AccountNumber: a.generateAccountNumber(),
			CreatedAt:     &now,
			UpdatedAt:     &now,
			IsActive:      true,
			IsLocked:      false,
		}

		if err := tx.Create(&account).Error; err != nil {
			return err
		}

		accountOrgUser := accountModel.OrganizationAccount{
			OrganizationID: existingOrg.ID,
			AccountID:      account.ID,
			CreatedAt:      now,
			UpdatedAt:      now,
			IsActive:       true,
			IsDeleted:      false,
		}

		if err := tx.Create(&accountOrgUser).Error; err != nil {
			return err
		}

		createdAccount = account
		return nil
	})

	if err != nil {
		if fiberErr, ok := err.(*fiber.Error); ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":  "error",
				"message": fiberErr.Message,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction failed",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":  "success",
		"message": "Account created successfully",
		"data":    createdAccount,
	})
}

func (a *AccountController) GetAccounts(c *fiber.Ctx) error {
	var accounts []accountModel.OrganizationAccount
	if err := database.DB.Preload("Account").Preload("Organization").Find(&accounts).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve accounts",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Accounts retrieved successfully",
		"data":    accounts,
	})
}

// GetAccount
func (a *AccountController) GetAccount(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var orgAccount accountModel.OrganizationAccount
	if err := database.DB.Preload("Account").Preload("Organization").
		Where("account_id = ?", accountID).First(&orgAccount).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve account",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account retrieved successfully",
		"data":    orgAccount,
	})
}

// Helper function to generate a unique account number (this should be implemented based on your business logic)
func (a *AccountController) generateAccountNumber() string {
	// Implement logic to generate a unique account number
	// For example, you could use a combination of a timestamp and a random number
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

type CreditRequest struct {
	ChallanNo       string `json:"challan_no"`
	AccountNumber   string `json:"account_number"`
	ChallanTypeCode string `json:"challan_type_code"`
}

type ChallanVerifyResponse struct {
	Status string `json:"status"`
	Data   struct {
		ChallanNo                   string  `json:"challan_no"`
		Amount                      string  `json:"amount"`
		IsVerified                  bool    `json:"is_verified"`
		VerificationStatus          string  `json:"verification_status"`
		ReasonOfVerificationFailure *string `json:"reason_of_verification_failure"`
	} `json:"data"`
}

// Credit handles balance crediting
func (a *AccountController) Credit(c *fiber.Ctx) error {
	var req CreditRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	// Prepare request body for challan verification
	requestData := map[string]string{
		"challan_no":        req.ChallanNo,
		"account_number":    req.AccountNumber,
		"challan_type_code": req.ChallanTypeCode,
	}
	jsonData, _ := json.Marshal(requestData)

	// Get and sanitize base URL
	baseURL := os.Getenv("EKDAK_BACKEND_API_URL")
	if baseURL == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "EKDAK_BACKEND_API_URL is not set",
		})
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	verifyURL := fmt.Sprintf("%s/challan/verify_challan_input/", baseURL)

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", verifyURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("❌ Error creating request:", err)
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to create challan verification request",
			"error":   err.Error(),
		})
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", c.Get("Authorization"))

	// Execute HTTP request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to call challan verification API",
			"error":   err.Error(),
		})
	}
	defer resp.Body.Close()

	// Decode response
	var challanResp ChallanVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&challanResp); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to parse challan verification response",
			"error":   err.Error(),
		})
	}

	if !challanResp.Data.IsVerified {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Challan not verified",
			"data": fiber.Map{
				"challan_no": challanResp.Data.ChallanNo,
				"reason":     challanResp.Data.ReasonOfVerificationFailure,
			},
		})
	}

	// Start DB transaction
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		// Lock the target account for update
		var targetAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("account_number = ?", req.AccountNumber).
			First(&targetAccount).Error; err != nil {
			return fiber.NewError(fiber.StatusNotFound, "No account found with this account number")
		}

		// Check if challan already exists (duplicate reference)
		var existingLedger accountModel.AccountLedger
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("reference = ?", challanResp.Data.ChallanNo).
			First(&existingLedger).Error; err == nil {
			return fiber.NewError(fiber.StatusBadRequest, "Challan already used")
		}

		// Parse and convert amount
		amountStr := strings.ReplaceAll(challanResp.Data.Amount, ",", "")
		amount, err := strconv.ParseFloat(amountStr, 64)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid amount format")
		}

		// Create ledger entry
		ledger := accountModel.AccountLedger{
			RecipientID: targetAccount.ID,
			SenderID:    targetAccount.ID, // same account for now
			//OrganizationID: organization.Organization{ID: targetAccount.ID},
			Credit:         &amount,
			Reference:      challanResp.Data.ChallanNo,
			IsAutoVerified: true,
			StatusActive:   1,
			IsDelete:       0,
			CreatedAt:      ptrTime(time.Now()),
			UpdatedAt:      ptrTime(time.Now()),
		}
		if err := tx.Create(&ledger).Error; err != nil {
			return err
		}

		// Update balance
		targetAccount.CurrentBalance += amount
		if err := tx.Save(&targetAccount).Error; err != nil {
			return err
		}

		return nil
	})

	// Handle transaction result
	if err != nil {
		if fiberErr, ok := err.(*fiber.Error); ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":  "error",
				"message": fiberErr.Message,
			})
		}
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction failed",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":  "success",
		"message": "Balance credited successfully",
	})
}

//DPMG Self Credit Balance
//func (a *AccountController) DPMGSelfCredit(c *fiber.Ctx) error {
//	var req struct {
//		DocumentPath   string  `json:"document_path"`
//		Amount         float64 `json:"amount"`
//		AccountNumber  string  `json:"account_number"`
//		Reference      string  `json:"reference"`
//	}
//	if err := c.BodyParser(&req); err != nil {
//		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "Invalid request", "error": err.Error()})
//	}
//	if req.AccountNumber == "" || req.Amount <= 0 || req.Reference == "" {
//		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "All fields are required and amount must be positive"})
//	}
//	// Start DB transaction
//	err := database.DB.Transaction(func(tx *gorm.DB) error {
//		// Lock account balance
//		var toAccount accountModel.Account
//		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
//			Where("account_number = ?", req.AccountNumber).First(&toAccount).Error; err != nil {
//			return fiber.NewError(fiber.StatusNotFound, "Account not found for credit")
//		}
//
//		// get token user id
//		userInfo := c.Locals("user").(map[string]interface{})
//		var toUser user.User
//		if err := database.DB.Where("id = ?", userInfo["id"]).First(&toUser).Error; err != nil {
//			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"status": "error", "message": "Target user not found"})
//		}
//
//
//		// Create ledger entry
//		ledger := accountModel.AccountLedger{
//			RecipientID:    toUser.ID,
//			SenderID:       toUser.ID, // self credit
//			Reference:      req.Reference,
//			Credit:         &req.Amount,
//			IsAutoVerified: true,
//			StatusActive:   1,
//			IsDelete:       0,
//
//			ToAccount:   &toAccount.ID,
//			FromAccount: &toAccount.ID,
//			ApprovalStatus: 1, // auto approved
//			ApprovedBy:     &toUser.ID,
//			ApprovedAt:     ptrTime(time.Now()),
//			VerifiedBy:     &toUser.ID,
//			VerifiedAt:     ptrTime(time.Now()),
//			CreatedAt:      ptrTime(time.Now()),
//			UpdatedAt:      ptrTime(time.Now()),
//		}
//		if err := tx.Create(&ledger).Error; err != nil {
//			return err
//		}
//
//		// Update balance
//		toAccount.CurrentBalance += req.Amount
//		if err := tx.Save(&toAccount).Error; err != nil {
//			return err
//		}
//
//		// Save document if provided
//		if req.DocumentPath != "" {
//			doc := accountModel.LedgerUpdateDocument{
//				AccountLedgerID: ledger.ID,
//				Path:    req.DocumentPath,
//				CreatedAt:       ptrTime(time.Now()),
//				UpdatedAt:       ptrTime(time.Now()),
//			}
//			if err := tx.Create(&doc).Error; err != nil {
//				return err
//			}
//		}
//		return nil
//	})
//
//	if err != nil {
//		if fiberErr, ok := err.(*fiber.Error); ok {
//			return c.Status(fiberErr.Code).JSON(fiber.Map{
//				"status":  "error",
//				"message": fiberErr.Message,
//			})
//		}
//		return c.Status(500).JSON(fiber.Map{
//			"status":  "error",
//			"message": "Transaction failed",
//			"error":   err.Error(),
//		})
//	}
//
//	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
//		"status":  "success",
//		"message": "Balance credited successfully",
//	}
//
//}

func (a *AccountController) Debit(c *fiber.Ctx) error {
	userInfo := c.Locals("user").(map[string]interface{})
	permissions := c.Locals("permissions").([]string)

	var req struct {
		AccountNumber   string  `json:"account_number"`
		RequestToUUID   string  `json:"request_to"`
		Reference       string  `json:"reference"`
		Credit          float64 `json:"credit"`
		Debit           float64 `json:"debit"`
		OrderID         *uint   `json:"order_id"`
		DocumentOrderID *uint   `json:"document_order_id"`
		StandardOrderID *uint   `json:"standard_order_id"`
		ServiceName     string  `json:"service_name"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "Invalid request", "error": err.Error()})
	}

	var allPermissions [][]string
	for _, p := range permissions {
		allPermissions = append(allPermissions, strings.Split(p, "."))
	}

	allowedBiliRoles := []string{"bili-operator", "bili-admin"}
	allowedStdRoles := []string{"standard-operator", "standard-admin"}
	allowedDwRoles := []string{"dw-operator", "dw-admin"}
	//allowedSuperRoles := []string{"super-admin"}

	checkRole := func(allowed []string) bool {
		for _, perm := range allPermissions {
			if len(perm) > 1 && contains(allowed, perm[1]) {
				return true
			}
		}
		return false
	}

	//isSuper := checkRole(allowedSuperRoles)
	isCorporate := checkRole(allowedBiliRoles)
	isStandard := checkRole(allowedStdRoles)
	isDocument := checkRole(allowedDwRoles)

	// Get debit initiator user
	var fromUser user.User
	if err := database.DB.Where("id = ?", userInfo["id"]).First(&fromUser).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Invalid user"})
	}

	// Get target user
	var toUser user.User
	if err := database.DB.Where("uuid = ?", req.RequestToUUID).First(&toUser).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"status": "error", "message": "Target user not found"})
	}

	// Get user accounts
	var fromAccount, toAccount accountModel.Account
	if err := database.DB.Where("id = ?", fromUser.ID).First(&fromAccount).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"status": "error", "message": "User account not found"})
	}
	if err := database.DB.Where("account_number = ? AND id = ?", req.AccountNumber, toUser.ID).First(&toAccount).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"status": "error", "message": "Target account not found"})
	}

	if req.AccountNumber == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "Account number is empty"})
	}

	// Start DB transaction
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// Lock account balance
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", toAccount.ID).First(&toAccount).Error; err != nil {
			return fiber.NewError(fiber.StatusNotFound, "Account not found for debit")
		}

		// Check sufficient balance
		if toAccount.CurrentBalance < req.Debit {
			return fiber.NewError(fiber.StatusBadRequest, "Insufficient balance")
		}

		// Create ledger
		ledger := accountModel.AccountLedger{
			SenderID:     fromAccount.ID,
			RecipientID:  toAccount.ID,
			Debit:        &req.Debit,
			Credit:       nil,
			Reference:    req.Reference,
			StatusActive: 1,
			IsDelete:     0,
			CreatedAt:    ptrTime(time.Now()),
			UpdatedAt:    ptrTime(time.Now()),
			ApprovedBy:   nil,
		}

		// Order association
		if isCorporate && req.OrderID != nil {
			ledger.OrderID = req.OrderID
		} else if isDocument && req.DocumentOrderID != nil {
			ledger.OrderID = req.DocumentOrderID
		} else if isStandard && req.StandardOrderID != nil {
			ledger.OrderID = req.StandardOrderID
		}

		if err := tx.Create(&ledger).Error; err != nil {
			return err
		}

		// Update balance
		toAccount.CurrentBalance -= req.Debit
		if err := tx.Save(&toAccount).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		if fiberErr, ok := err.(*fiber.Error); ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":  "error",
				"message": fiberErr.Message,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Debit failed",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":  "success",
		"message": "Balance debited successfully",
		"data": fiber.Map{
			"balance": toAccount.CurrentBalance,
		},
	})
}

// contains checks if a string slice contains a given value
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// GetDebitsByAccountID
// GetCreditsByAccountID
// GetTransactionsByAccountID
// GetTransactionsByOrganizationID
// GetTransactionsByDateRange
// GetTransactionsByType
// GetBalanceByAccountID
// GetBalanceByOrganizationID
// GetAllAccountsByOrganizationID
// GetAllAccounts
// UpdateAccount
// DeleteAccount
// TransferFunds
// CreateTransaction
// GetTransaction
// UpdateTransaction
// DeleteTransaction
// GenerateAccountStatement
// GenerateOrganizationStatement
// LockAccount
// UnlockAccount
// ActivateAccount
// DeactivateAccount
// ApproveTransaction
// RejectTransaction
// GetPendingTransactions
// GetFailedTransactions

func (a *AccountController) GetBalanceByAccountID(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve account balance",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account balance retrieved successfully",
		"data": fiber.Map{
			"account_id":      account.ID,
			"current_balance": account.CurrentBalance,
		},
	})
}

// GetDebitsByAccountID returns all debit transactions for a given account
func (a *AccountController) GetDebitsByAccountID(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var ledgers []accountModel.AccountLedger
	if err := database.DB.Where("recipient_id = ? AND debit IS NOT NULL", accountID).
		Order("created_at DESC").Find(&ledgers).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve debit transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Debit transactions retrieved successfully",
		"data":    ledgers,
	})
}

// GetCreditsByAccountID returns all credit transactions for a given account
func (a *AccountController) GetCreditsByAccountID(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var ledgers []accountModel.AccountLedger
	if err := database.DB.Where("recipient_id = ? AND credit IS NOT NULL", accountID).
		Order("created_at DESC").Find(&ledgers).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve credit transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Credit transactions retrieved successfully",
		"data":    ledgers,
	})
}

// GetTransactionsByAccountID returns all transactions for a given account
func (a *AccountController) GetTransactionsByAccountID(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var ledgers []accountModel.AccountLedger
	if err := database.DB.Where("recipient_id = ? OR sender_id = ?", accountID, accountID).
		Order("created_at DESC").Find(&ledgers).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transactions retrieved successfully",
		"data":    ledgers,
	})
}

// GetTransactionsByOrganizationID returns all transactions for a given organization
func (a *AccountController) GetTransactionsByOrganizationID(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Organization ID is required",
		})
	}

	var ledgers []accountModel.AccountLedger
	if err := database.DB.Joins("JOIN organization_accounts oa ON oa.account_id = account_ledgers.recipient_id").
		Where("oa.organization_id = ?", orgID).
		Order("account_ledgers.created_at DESC").Find(&ledgers).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve organization transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Organization transactions retrieved successfully",
		"data":    ledgers,
	})
}

// GetTransactionsByDateRange returns transactions within a date range
func (a *AccountController) GetTransactionsByDateRange(c *fiber.Ctx) error {
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	if startDate == "" || endDate == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Start date and end date are required",
		})
	}

	var ledgers []accountModel.AccountLedger
	if err := database.DB.Where("created_at BETWEEN ? AND ?", startDate, endDate).
		Order("created_at DESC").Find(&ledgers).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve transactions by date range",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transactions retrieved successfully",
		"data":    ledgers,
	})
}

// GetTransactionsByType returns transactions filtered by type
func (a *AccountController) GetTransactionsByType(c *fiber.Ctx) error {
	transactionType := c.Query("type")
	if transactionType == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction type is required (credit or debit)",
		})
	}

	var ledgers []accountModel.AccountLedger
	var err error

	if transactionType == "credit" {
		err = database.DB.Where("credit IS NOT NULL").Order("created_at DESC").Find(&ledgers).Error
	} else if transactionType == "debit" {
		err = database.DB.Where("debit IS NOT NULL").Order("created_at DESC").Find(&ledgers).Error
	} else {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid transaction type. Use 'credit' or 'debit'",
		})
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve transactions by type",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transactions retrieved successfully",
		"data":    ledgers,
	})
}

// GetBalanceByOrganizationID returns the total balance for a given organization
func (a *AccountController) GetBalanceByOrganizationID(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Organization ID is required",
		})
	}

	var totalBalance float64
	if err := database.DB.Table("accounts").
		Joins("JOIN organization_accounts ON organization_accounts.account_id = accounts.id").
		Where("organization_accounts.organization_id = ?", orgID).
		Select("SUM(accounts.current_balance)").Scan(&totalBalance).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve organization balance",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Organization balance retrieved successfully",
		"data": fiber.Map{
			"organization_id": orgID,
			"total_balance":   totalBalance,
		},
	})
}

// GetAllAccountsByOrganizationID returns all accounts for a given organization
func (a *AccountController) GetAllAccountsByOrganizationID(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Organization ID is required",
		})
	}

	var orgAccounts []accountModel.OrganizationAccount
	if err := database.DB.Preload("Account").Preload("Organization").
		Where("organization_id = ?", orgID).Find(&orgAccounts).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve organization accounts",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Organization accounts retrieved successfully",
		"data":    orgAccounts,
	})
}

// GetAllAccounts returns all accounts
func (a *AccountController) GetAllAccounts(c *fiber.Ctx) error {
	var accounts []accountModel.Account
	if err := database.DB.Find(&accounts).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve all accounts",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "All accounts retrieved successfully",
		"data":    accounts,
	})
}

// UpdateAccount updates account details
func (a *AccountController) UpdateAccount(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var updateData accountModel.Account
	if err := c.BodyParser(&updateData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find account",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	updateData.UpdatedAt = &now
	if err := database.DB.Model(&account).Updates(updateData).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to update account",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account updated successfully",
		"data":    account,
	})
}

// DeleteAccount deletes an account
func (a *AccountController) DeleteAccount(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find account",
			"error":   err.Error(),
		})
	}

	if err := database.DB.Delete(&account).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to delete account",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account deleted successfully",
	})
}

// TransferFunds transfers funds between accounts
func (a *AccountController) TransferFunds(c *fiber.Ctx) error {
	var req struct {
		FromAccountID string  `json:"from_account_id"`
		ToAccountID   string  `json:"to_account_id"`
		Amount        float64 `json:"amount"`
		Reference     string  `json:"reference"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
	}

	if req.Amount <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Amount must be greater than zero",
		})
	}

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var fromAccount, toAccount accountModel.Account

		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", req.FromAccountID).First(&fromAccount).Error; err != nil {
			return fiber.NewError(fiber.StatusNotFound, "From account not found")
		}

		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", req.ToAccountID).First(&toAccount).Error; err != nil {
			return fiber.NewError(fiber.StatusNotFound, "To account not found")
		}

		if fromAccount.CurrentBalance < req.Amount {
			return fiber.NewError(fiber.StatusBadRequest, "Insufficient balance")
		}

		// Create ledger entries
		debitLedger := accountModel.AccountLedger{
			SenderID:     fromAccount.ID,
			RecipientID:  fromAccount.ID,
			Debit:        &req.Amount,
			Reference:    req.Reference,
			StatusActive: 1,
			IsDelete:     0,
			CreatedAt:    ptrTime(time.Now()),
			UpdatedAt:    ptrTime(time.Now()),
		}

		creditLedger := accountModel.AccountLedger{
			SenderID:     fromAccount.ID,
			RecipientID:  toAccount.ID,
			Credit:       &req.Amount,
			Reference:    req.Reference,
			StatusActive: 1,
			IsDelete:     0,
			CreatedAt:    ptrTime(time.Now()),
			UpdatedAt:    ptrTime(time.Now()),
		}

		if err := tx.Create(&debitLedger).Error; err != nil {
			return err
		}

		if err := tx.Create(&creditLedger).Error; err != nil {
			return err
		}

		// Update balances
		fromAccount.CurrentBalance -= req.Amount
		toAccount.CurrentBalance += req.Amount

		if err := tx.Save(&fromAccount).Error; err != nil {
			return err
		}

		if err := tx.Save(&toAccount).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		if fiberErr, ok := err.(*fiber.Error); ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":  "error",
				"message": fiberErr.Message,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Transfer failed",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Funds transferred successfully",
	})
}

// CreateTransaction creates a new transaction
func (a *AccountController) CreateTransaction(c *fiber.Ctx) error {
	var req accountModel.AccountLedger
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	req.CreatedAt = &now
	req.UpdatedAt = &now
	req.StatusActive = 1
	req.IsDelete = 0

	if err := database.DB.Create(&req).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to create transaction",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":  "success",
		"message": "Transaction created successfully",
		"data":    req,
	})
}

// GetTransaction returns a specific transaction
func (a *AccountController) GetTransaction(c *fiber.Ctx) error {
	transactionID := c.Params("id")
	if transactionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction ID is required",
		})
	}

	var ledger accountModel.AccountLedger
	if err := database.DB.Where("id = ?", transactionID).First(&ledger).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Transaction not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve transaction",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transaction retrieved successfully",
		"data":    ledger,
	})
}

// UpdateTransaction updates a transaction
func (a *AccountController) UpdateTransaction(c *fiber.Ctx) error {
	transactionID := c.Params("id")
	if transactionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction ID is required",
		})
	}

	var updateData accountModel.AccountLedger
	if err := c.BodyParser(&updateData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
	}

	var ledger accountModel.AccountLedger
	if err := database.DB.Where("id = ?", transactionID).First(&ledger).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Transaction not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find transaction",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	updateData.UpdatedAt = &now
	if err := database.DB.Model(&ledger).Updates(updateData).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to update transaction",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transaction updated successfully",
		"data":    ledger,
	})
}

// DeleteTransaction deletes a transaction
func (a *AccountController) DeleteTransaction(c *fiber.Ctx) error {
	transactionID := c.Params("id")
	if transactionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction ID is required",
		})
	}

	var ledger accountModel.AccountLedger
	if err := database.DB.Where("id = ?", transactionID).First(&ledger).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Transaction not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find transaction",
			"error":   err.Error(),
		})
	}

	// Soft delete
	now := time.Now()
	ledger.IsDelete = 1
	ledger.UpdatedAt = &now

	if err := database.DB.Save(&ledger).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to delete transaction",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transaction deleted successfully",
	})
}

// GenerateAccountStatement generates a statement for an account
func (a *AccountController) GenerateAccountStatement(c *fiber.Ctx) error {
	accountID := c.Params("id")
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find account",
			"error":   err.Error(),
		})
	}

	query := database.DB.Where("recipient_id = ? OR sender_id = ?", accountID, accountID)
	if startDate != "" && endDate != "" {
		query = query.Where("created_at BETWEEN ? AND ?", startDate, endDate)
	}

	var transactions []accountModel.AccountLedger
	if err := query.Order("created_at DESC").Find(&transactions).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account statement generated successfully",
		"data": fiber.Map{
			"account":      account,
			"transactions": transactions,
			"statement_period": fiber.Map{
				"start_date": startDate,
				"end_date":   endDate,
			},
		},
	})
}

// GenerateOrganizationStatement generates a statement for an organization
func (a *AccountController) GenerateOrganizationStatement(c *fiber.Ctx) error {
	orgID := c.Params("id")
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Organization ID is required",
		})
	}

	query := database.DB.Joins("JOIN organization_accounts oa ON oa.account_id = account_ledgers.recipient_id").
		Where("oa.organization_id = ?", orgID)

	if startDate != "" && endDate != "" {
		query = query.Where("account_ledgers.created_at BETWEEN ? AND ?", startDate, endDate)
	}

	var transactions []accountModel.AccountLedger
	if err := query.Order("account_ledgers.created_at DESC").Find(&transactions).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve organization transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Organization statement generated successfully",
		"data": fiber.Map{
			"organization_id": orgID,
			"transactions":    transactions,
			"statement_period": fiber.Map{
				"start_date": startDate,
				"end_date":   endDate,
			},
		},
	})
}

// LockAccount locks an account
func (a *AccountController) LockAccount(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find account",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	account.IsLocked = true
	account.UpdatedAt = &now

	if err := database.DB.Save(&account).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to lock account",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account locked successfully",
		"data":    account,
	})
}

// UnlockAccount unlocks an account
func (a *AccountController) UnlockAccount(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find account",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	account.IsLocked = false
	account.UpdatedAt = &now

	if err := database.DB.Save(&account).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to unlock account",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account unlocked successfully",
		"data":    account,
	})
}

// ActivateAccount activates an account
func (a *AccountController) ActivateAccount(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find account",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	account.IsActive = true
	account.UpdatedAt = &now

	if err := database.DB.Save(&account).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to activate account",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account activated successfully",
		"data":    account,
	})
}

// DeactivateAccount deactivates an account
func (a *AccountController) DeactivateAccount(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Account ID is required",
		})
	}

	var account accountModel.Account
	if err := database.DB.Where("id = ?", accountID).First(&account).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find account",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	account.IsActive = false
	account.UpdatedAt = &now

	if err := database.DB.Save(&account).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to deactivate account",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Account deactivated successfully",
		"data":    account,
	})
}

// ApproveTransaction approves a transaction
func (a *AccountController) ApproveTransaction(c *fiber.Ctx) error {
	transactionID := c.Params("id")
	if transactionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction ID is required",
		})
	}

	userInfo := c.Locals("user").(map[string]interface{})
	approverID := uint(userInfo["id"].(float64))

	var ledger accountModel.AccountLedger
	if err := database.DB.Where("id = ?", transactionID).First(&ledger).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Transaction not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find transaction",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	ledger.ApprovedBy = &approverID
	ledger.IsAutoVerified = true
	ledger.StatusActive = 1
	ledger.UpdatedAt = &now

	if err := database.DB.Save(&ledger).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to approve transaction",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transaction approved successfully",
		"data":    ledger,
	})
}

// RejectTransaction rejects a transaction
func (a *AccountController) RejectTransaction(c *fiber.Ctx) error {
	transactionID := c.Params("id")
	if transactionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction ID is required",
		})
	}

	var ledger accountModel.AccountLedger
	if err := database.DB.Where("id = ?", transactionID).First(&ledger).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Transaction not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to find transaction",
			"error":   err.Error(),
		})
	}

	now := time.Now()
	ledger.StatusActive = 0
	ledger.UpdatedAt = &now

	if err := database.DB.Save(&ledger).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to reject transaction",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Transaction rejected successfully",
		"data":    ledger,
	})
}

// GetPendingTransactions returns all pending transactions
func (a *AccountController) GetPendingTransactions(c *fiber.Ctx) error {
	var ledgers []accountModel.AccountLedger
	if err := database.DB.Where("approved_by IS NULL AND status_active = 1 AND is_delete = 0").
		Order("created_at DESC").Find(&ledgers).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve pending transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Pending transactions retrieved successfully",
		"data":    ledgers,
	})
}

// GetFailedTransactions returns all failed transactions
func (a *AccountController) GetFailedTransactions(c *fiber.Ctx) error {
	var ledgers []accountModel.AccountLedger
	if err := database.DB.Where("status_active = 0 AND is_delete = 0").
		Order("created_at DESC").Find(&ledgers).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve failed transactions",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Failed transactions retrieved successfully",
		"data":    ledgers,
	})
}

// ptrTime converts a time.Time to *time.Time
func ptrTime(t time.Time) *time.Time {
	return &t
}

// GetUserAccount retrieves the logged-in user's account information
func (a *AccountController) GetUserAccount(c *fiber.Ctx) error {
	// Debug: Check what's in the context
	logger.Info("Debugging user context...")

	// Try to get user claims from the JWT token - use map[string]interface{} since that's what's actually stored
	userClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		// Let's also check what's actually in the context
		userLocal := c.Locals("user")
		logger.Error(fmt.Sprintf("Unable to extract user claims from token. Context contains: %+v", userLocal), nil)

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid or missing authentication token",
		})
	}

	logger.Info(fmt.Sprintf("User claims found: %+v", userClaims))

	// Extract user UUID from claims
	userUUID, ok := userClaims["uuid"].(string)
	if !ok || userUUID == "" {
		logger.Error("User UUID not found in token claims", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "User UUID not found in token",
		})
	}

	// Find user by UUID
	var userRecord user.User
	if err := a.db.Where("uuid = ?", userUUID).First(&userRecord).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("User not found with UUID: %s", userUUID), err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "User not found",
			})
		}
		logger.Error("Database error while fetching user", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Find UserAccount by user ID
	var userAccount accountModel.UserAccount
	if err := a.db.Where("user_id = ?", userRecord.ID).First(&userAccount).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("UserAccount not found for user ID: %d", userRecord.ID), err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "User account not found",
			})
		}
		logger.Error("Database error while fetching user account", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Find Account details by account ID
	var accountRecord accountModel.Account
	if err := a.db.Where("id = ?", userAccount.AccountID).First(&accountRecord).Error; err != nil {
		logger.Error("Database error while fetching account details", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Prepare response data
	accountInfo := fiber.Map{
		"user_info": fiber.Map{
			"id":             userRecord.ID,
			"uuid":           userRecord.Uuid,
			"username":       userRecord.Username,
			"legal_name":     userRecord.LegalName,
			"phone":          userRecord.Phone,
			"email":          userRecord.Email,
			"phone_verified": userRecord.PhoneVerified,
			"email_verified": userRecord.EmailVerified,
		},
		"account_info": fiber.Map{
			"id":              accountRecord.ID,
			"account_number":  accountRecord.AccountNumber,
			"current_balance": accountRecord.CurrentBalance,
			"account_type":    accountRecord.AccountType,
			"is_active":       accountRecord.IsActive,
			"is_locked":       accountRecord.IsLocked,
			"max_limit":       accountRecord.MaxLimit,
			"balance_type":    accountRecord.BalanceType,
			"currency":        accountRecord.Currency,
			"created_at":      accountRecord.CreatedAt,
			"updated_at":      accountRecord.UpdatedAt,
		},
		"user_account_info": fiber.Map{
			"id":         userAccount.ID,
			"created_by": userAccount.CreatedBy,
			"updated_by": userAccount.UpdatedBy,
			"is_active":  userAccount.IsActive,
			"created_at": userAccount.CreatedAt,
			"updated_at": userAccount.UpdatedAt,
		},
	}

	logger.Success(fmt.Sprintf("Successfully retrieved account information for user: %s", userUUID))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "User account information retrieved successfully",
		"data":    accountInfo,
	})
}
