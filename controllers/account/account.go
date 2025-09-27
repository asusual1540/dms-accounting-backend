package account

import (
	"bytes"
	"dms-accounting/database"
	"dms-accounting/logger"
	accountModel "dms-accounting/models/account"
	"dms-accounting/models/organization"
	"dms-accounting/models/user"
	"dms-accounting/types"
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

// Helper function to create PostPaidBill events
func (a *AccountController) CreateBillEvent(tx *gorm.DB, billID uint, createdBy uint, eventType string, notes *string) error {
	event := accountModel.PostPaidBillEvent{
		PostPaidBillID: billID,
		CreatedBy:      createdBy,
		EventType:      eventType,
		EventTime:      time.Now(),
		Notes:          notes,
	}

	if err := tx.Create(&event).Error; err != nil {
		logger.Error(fmt.Sprintf("Failed to create bill event: %s for bill ID: %d", eventType, billID), err)
		return err
	}

	logger.Info(fmt.Sprintf("Bill event created: %s for bill ID: %d by user: %d", eventType, billID, createdBy))
	return nil
}

// Helper function to check if bill has a specific event
func (a *AccountController) HasBillEvent(billID uint, eventType string) (bool, *time.Time) {
	var event accountModel.PostPaidBillEvent
	err := a.db.Where("post_paid_bill_id = ? AND event_type = ?", billID, eventType).
		Order("event_time DESC").First(&event).Error
	if err != nil {
		return false, nil
	}
	return true, &event.EventTime
}

// Helper function to check if bill has the latest event of a specific type
// This function is optimized to get the most recent event of the specified type
func (a *AccountController) HasLatestBillEvent(billID uint, eventType string) (bool, *time.Time) {
	var event accountModel.PostPaidBillEvent
	err := a.db.Where("post_paid_bill_id = ? AND event_type = ?", billID, eventType).
		Order("event_time DESC").
		Limit(1).
		First(&event).Error
	if err != nil {
		return false, nil
	}
	return true, &event.EventTime
}

// Helper function to get all latest events for multiple event types for a bill
// This is more efficient when checking multiple event types for the same bill
func (a *AccountController) GetLatestBillEvents(billID uint, eventTypes []string) map[string]*accountModel.PostPaidBillEvent {
	var events []accountModel.PostPaidBillEvent
	result := make(map[string]*accountModel.PostPaidBillEvent)

	// Initialize result map with nil values
	for _, eventType := range eventTypes {
		result[eventType] = nil
	}

	// Get all events for the bill with the specified types
	err := a.db.Where("post_paid_bill_id = ? AND event_type IN ?", billID, eventTypes).
		Order("event_time DESC").
		Find(&events).Error

	if err != nil {
		return result
	}

	// For each event type, find the latest event
	for _, eventType := range eventTypes {
		for i := range events {
			if events[i].EventType == eventType && result[eventType] == nil {
				result[eventType] = &events[i]
				break
			}
		}
	}

	return result
}

// Helper function to get all events for a bill
func (a *AccountController) GetAllBillEvents(billID uint) []accountModel.PostPaidBillEvent {
	var events []accountModel.PostPaidBillEvent

	err := a.db.Where("post_paid_bill_id = ?", billID).
		Order("event_time DESC").
		Find(&events).Error

	if err != nil {
		return []accountModel.PostPaidBillEvent{}
	}

	return events
}

// Helper function to get bill status based on events (optimized version)
func (a *AccountController) GetBillStatus(billID uint) fiber.Map {
	eventTypes := []string{"sent", "paid", "approved"}
	events := a.GetLatestBillEvents(billID, eventTypes)

	var sentAt, paidAt, approvedAt *time.Time
	isSent := events["sent"] != nil
	isPaid := events["paid"] != nil
	isApproved := events["approved"] != nil

	if isSent {
		sentAt = &events["sent"].EventTime
	}
	if isPaid {
		paidAt = &events["paid"].EventTime
	}
	if isApproved {
		approvedAt = &events["approved"].EventTime
	}

	return fiber.Map{
		"is_sent":     isSent,
		"sent_at":     sentAt,
		"is_paid":     isPaid,
		"paid_at":     paidAt,
		"is_approved": isApproved,
		"approved_at": approvedAt,
	}
}

// Helper function to format bill response with status from events
func (a *AccountController) FormatBillResponse(bill accountModel.PostPaidBill) fiber.Map {
	billStatus := a.GetBillStatus(bill.ID)

	return fiber.Map{
		"ID":                bill.ID,
		"bill_uuid":         bill.BillUuid,
		"Amount":            bill.Amount,
		"SenderAccountID":   bill.SenderAccountID,
		"ReceiverAccountID": bill.ReceiverAccountID,
		"ApproverAccountID": bill.ApproverAccountID,
		"Reference":         bill.Reference,
		"is_sent":           billStatus["is_sent"],
		"sent_at":           billStatus["sent_at"],
		"is_paid":           billStatus["is_paid"],
		"paid_at":           billStatus["paid_at"],
		"is_approved":       billStatus["is_approved"],
		"approved_at":       billStatus["approved_at"],
		"CreatedAt":         bill.CreatedAt,
		"UpdatedAt":         bill.UpdatedAt,
		"IsDelete":          bill.IsDelete,
	}
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
		var existingAccountOwner accountModel.AccountOwner
		if err := tx.Where("user_id = ? AND org_id = ?", existingUser.ID, existingOrg.ID).
			First(&existingAccountOwner).Error; err == nil {
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

		accountOwner := accountModel.AccountOwner{
			UserID:    &existingUser.ID,
			AccountID: &account.ID,
			OrgID:     &existingOrg.ID,
		}

		if err := tx.Create(&accountOwner).Error; err != nil {
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
	var accountOwners []accountModel.AccountOwner
	if err := database.DB.Preload("Account").Preload("Org").Preload("User").Find(&accountOwners).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve accounts",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Accounts retrieved successfully",
		"data":    accountOwners,
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

	var accountOwner accountModel.AccountOwner
	if err := database.DB.Preload("Account").Preload("Org").Preload("User").
		Where("account_id = ?", accountID).First(&accountOwner).Error; err != nil {
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
		"data":    accountOwner,
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
			//OrganizationID: organization.Organization{ID: targetAccount.ID},
			Credit:         &amount,
			Reference:      challanResp.Data.ChallanNo,
			IsAutoVerified: true,
			StatusActive:   1,
			IsDelete:       0,
			CreatedAt:      time.Now(),
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

/*==================================================================================================================
| Operator Debit Part
===================================================================================================================*/

type DebitRequest struct {
	Reference string  `json:"reference"`
	Amount    float64 `json:"amount"`
	Barcode   string  `json:"barcode"` // Optional barcode field
}

func (r DebitRequest) Validate() string {
	// Ensure that login identifier is provided (either email or phone)
	if r.Reference == "" {
		return "Either reference is required"
	}
	if r.Barcode == "" {
		return "Either barcode is required"
	}

	// Validate amount
	if r.Amount <= 0 {
		return "Amount must be greater than zero"
	}

	return ""
}

// Helper function to format ledger entry in the same structure as ledger list
func (a *AccountController) formatLedgerEntry(entry accountModel.AccountLedger) fiber.Map {
	// Calculate the amount and entry_type (either credit or debit based on which field has value)
	var amount float64
	var transactionType string
	var entryType string
	if entry.Credit != nil && *entry.Credit > 0 {
		amount = *entry.Credit
		transactionType = "credit"
		entryType = "credit"
	} else if entry.Debit != nil && *entry.Debit > 0 {
		amount = *entry.Debit
		transactionType = "debit"
		entryType = "debit"
	}

	entryData := fiber.Map{
		"id":               entry.ID,
		"amount":           amount,
		"reference":        entry.Reference,
		"transaction_type": transactionType,
		"entry_type":       entryType,
		"created_at":       entry.CreatedAt,
		"updated_at":       entry.UpdatedAt,
	}

	// Add current balances from ledger entry
	if entry.FromAccountCurrentBalance != nil {
		entryData["from_account_current_balance"] = *entry.FromAccountCurrentBalance
	}
	if entry.ToAccountCurrentBalance != nil {
		entryData["to_account_current_balance"] = *entry.ToAccountCurrentBalance
	}

	// Add from_account info
	if entry.FromAccountRef != nil {
		fromAccountData := fiber.Map{
			"id":             entry.FromAccountRef.ID,
			"account_number": entry.FromAccountRef.AccountNumber,
			"account_name":   entry.FromAccountRef.AccountName,
		}

		// Add account owner info if exists
		if entry.FromAccountRef.AccountOwner != nil {
			ownerInfo := fiber.Map{}
			if entry.FromAccountRef.AccountOwner.User != nil {
				ownerInfo["user"] = fiber.Map{
					"id":       entry.FromAccountRef.AccountOwner.User.ID,
					"username": entry.FromAccountRef.AccountOwner.User.Username,
					"uuid":     entry.FromAccountRef.AccountOwner.User.Uuid,
				}
			}
			if entry.FromAccountRef.AccountOwner.Admin != nil {
				ownerInfo["admin"] = fiber.Map{
					"id":       entry.FromAccountRef.AccountOwner.Admin.ID,
					"username": entry.FromAccountRef.AccountOwner.Admin.Username,
					"uuid":     entry.FromAccountRef.AccountOwner.Admin.Uuid,
				}
			}
			fromAccountData["account_owner"] = ownerInfo
		}

		entryData["from_account"] = fromAccountData
	}

	// Add to_account info
	toAccountData := fiber.Map{
		"id":             entry.ToAccountRef.ID,
		"account_number": entry.ToAccountRef.AccountNumber,
		"account_name":   entry.ToAccountRef.AccountName,
	}

	// Add account owner info if exists
	if entry.ToAccountRef.AccountOwner != nil {
		ownerInfo := fiber.Map{}
		if entry.ToAccountRef.AccountOwner.User != nil {
			ownerInfo["user"] = fiber.Map{
				"id":       entry.ToAccountRef.AccountOwner.User.ID,
				"username": entry.ToAccountRef.AccountOwner.User.Username,
				"uuid":     entry.ToAccountRef.AccountOwner.User.Uuid,
			}
		}
		if entry.ToAccountRef.AccountOwner.Admin != nil {
			ownerInfo["admin"] = fiber.Map{
				"id":       entry.ToAccountRef.AccountOwner.Admin.ID,
				"username": entry.ToAccountRef.AccountOwner.Admin.Username,
				"uuid":     entry.ToAccountRef.AccountOwner.Admin.Uuid,
			}
		}
		toAccountData["account_owner"] = ownerInfo
	}

	entryData["to_account"] = toAccountData

	return entryData
}

func (a *AccountController) OperatorDebit(c *fiber.Ctx) error {
	var req DebitRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: fmt.Errorf("Error parsing request body: %v", err).Error(),
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}
	if v := req.Validate(); v != "" {
		logger.Error(v, nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: v,
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	// Try to get user claims from the JWT token - use map[string]interface{} since that's what's actually stored
	debitUserClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		// Let's also check what's actually in the context
		userLocal := c.Locals("user")
		logger.Error(fmt.Sprintf("Unable to extract user claims from token. Context contains: %+v", userLocal), nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid or missing authentication token",
		})
	}
	// Extract user UUID from claims
	debitUserUUID, ok := debitUserClaims["uuid"].(string)
	if !ok || debitUserUUID == "" {
		logger.Error("User UUID not found in token claims", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "User UUID not found in token",
		})
	}

	// Find user by UUID
	var debitUserRecord user.User
	if err := a.db.Where("uuid = ?", debitUserUUID).First(&debitUserRecord).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("User not found with UUID: %s", debitUserUUID), err)
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

	// Find AccountOwner by user ID
	var debitAccountOwner accountModel.AccountOwner
	if err := a.db.Where("user_id = ?", debitUserRecord.ID).First(&debitAccountOwner).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("AccountOwner not found for user ID: %d", debitUserRecord.ID), err)
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
	var debitUseraccountRecord accountModel.Account
	if err := a.db.Where("id = ?", *debitAccountOwner.AccountID).First(&debitUseraccountRecord).Error; err != nil {
		logger.Error("Database error while fetching account details", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Extract branch_code from user claims and generate account number
	branchCode, ok := debitUserClaims["branch_code"].(string)
	if !ok || branchCode == "" {
		logger.Error("Branch code not found in token claims", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Branch code not found in token",
		})
	}

	// Generate account number: S + branch_code
	accountNumber := "S" + branchCode
	logger.Info(fmt.Sprintf("Generated account number: %s from branch code: %s", accountNumber, branchCode))

	// Find the target account directly using generated account number
	var targetAccount accountModel.Account
	if err := a.db.Where("account_number = ?", accountNumber).First(&targetAccount).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("Account not found with account number: %s", accountNumber), err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found",
			})
		}
		logger.Error("Database error while fetching account", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Check if account has sufficient balance
	if targetAccount.CurrentBalance < req.Amount {
		logger.Error("Insufficient balance in account", nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Insufficient balance in account",
		})
	}

	// Create two ledger entries for proper double-entry bookkeeping

	// 1. Debit entry: Operator takes a Stamp and money enters into request user's personal account from target branch account
	// Store current balances BEFORE the transaction
	debitLedger := accountModel.AccountLedger{
		Debit:                     &req.Amount,
		Reference:                 req.Reference,
		Barcode:                   &req.Barcode,
		FromAccount:               &debitUseraccountRecord.ID,
		ToAccount:                 targetAccount.ID,                       // Target branch account
		FromAccountCurrentBalance: &debitUseraccountRecord.CurrentBalance, // Balance before transaction
		ToAccountCurrentBalance:   &targetAccount.CurrentBalance,          // Balance before transaction
		TransactionType:           "booking",
		StatusActive:              1,
		IsDelete:                  0,
		CreatedAt:                 time.Now(),
		UpdatedAt:                 ptrTime(time.Now()),
	}
	if err := a.db.Create(&debitLedger).Error; err != nil {
		logger.Error("Database error while creating debit ledger entry", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// 2. Credit entry: Operator takes money from user and money is credited to request user's personal account
	// Store current balance BEFORE the transaction
	creditLedger := accountModel.AccountLedger{
		Credit:                  &req.Amount,
		Reference:               req.Reference,
		Barcode:                 &req.Barcode,
		FromAccount:             nil,
		ToAccount:               debitUseraccountRecord.ID,              // Request user's personal account (money goes here from customer)
		ToAccountCurrentBalance: &debitUseraccountRecord.CurrentBalance, // Balance before transaction
		TransactionType:         "payment",
		StatusActive:            1,
		IsDelete:                0,
		CreatedAt:               time.Now(),
		UpdatedAt:               ptrTime(time.Now()),
	}
	if err := a.db.Create(&creditLedger).Error; err != nil {
		logger.Error("Database error while creating credit ledger entry", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Deduct amount from target account balance
	targetAccount.CurrentBalance -= req.Amount
	if err := a.db.Save(&targetAccount).Error; err != nil {
		logger.Error("Database error while updating target account balance", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Add amount to operator's account balance
	debitUseraccountRecord.CurrentBalance += req.Amount
	if err := a.db.Save(&debitUseraccountRecord).Error; err != nil {
		logger.Error("Database error while updating operator account balance", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Fetch the created ledger entries with preloaded relationships for response
	var debitLedgerWithRefs accountModel.AccountLedger
	if err := a.db.Preload("ToAccountRef").Preload("FromAccountRef").
		Preload("ToAccountRef.AccountOwner").Preload("ToAccountRef.AccountOwner.User").Preload("ToAccountRef.AccountOwner.Admin").
		Preload("FromAccountRef.AccountOwner").Preload("FromAccountRef.AccountOwner.User").Preload("FromAccountRef.AccountOwner.Admin").
		Where("id = ?", debitLedger.ID).First(&debitLedgerWithRefs).Error; err != nil {
		logger.Error("Error loading debit ledger relationships", err)
		// Continue without relationships if there's an error
		debitLedgerWithRefs = debitLedger
	}

	var creditLedgerWithRefs accountModel.AccountLedger
	if err := a.db.Preload("ToAccountRef").Preload("FromAccountRef").
		Preload("ToAccountRef.AccountOwner").Preload("ToAccountRef.AccountOwner.User").Preload("ToAccountRef.AccountOwner.Admin").
		Preload("FromAccountRef.AccountOwner").Preload("FromAccountRef.AccountOwner.User").Preload("FromAccountRef.AccountOwner.Admin").
		Where("id = ?", creditLedger.ID).First(&creditLedgerWithRefs).Error; err != nil {
		logger.Error("Error loading credit ledger relationships", err)
		// Continue without relationships if there's an error
		creditLedgerWithRefs = creditLedger
	}

	// For debugging, return user and account info
	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": "Operator debit endpoint",
		"data": fiber.Map{
			"debit_ledger":  a.formatLedgerEntry(debitLedgerWithRefs),
			"credit_ledger": a.formatLedgerEntry(creditLedgerWithRefs),
		},
	})
}

// operatorDebitbill
type OperatorDebitBillRequest struct {
	LedgerIds []uint `json:"ledger_ids"`
}

// bill uuis ganreted from post paid bill table
func BillUuidGenerator() string {
	return fmt.Sprintf("BILL-%d", time.Now().UnixNano())
}

func (a *AccountController) OperatorDebitbill(c *fiber.Ctx) error {
	var req OperatorDebitBillRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: fmt.Errorf("Error parsing request body: %v", err).Error(),
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}
	if len(req.LedgerIds) == 0 {
		logger.Error("No ledger IDs provided", nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: "No ledger IDs provided",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	// Extract user claims from JWT token
	userClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		userLocal := c.Locals("user")
		logger.Error(fmt.Sprintf("Unable to extract user claims from token. Context contains: %+v", userLocal), nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthorized access",
		})
	}

	// Extract user UUID from claims
	userUUID, ok := userClaims["uuid"].(string)
	if !ok || userUUID == "" {
		logger.Error("User UUID not found in token claims", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "User UUID not found in token",
		})
	}

	// Extract branch_code from user claims
	branchCode, ok := userClaims["branch_code"].(string)
	if !ok || branchCode == "" {
		logger.Error("Branch code not found in token claims", nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Branch code not found in token",
		})
	}

	// Find the current user's account (for sender/from_account)
	var senderUser user.User
	if err := a.db.Where("uuid = ?", userUUID).First(&senderUser).Error; err != nil {
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

	// Find the sender's account through AccountOwner
	var senderAccountOwner accountModel.AccountOwner
	if err := a.db.Preload("Account").Preload("User").Where("user_id = ?", senderUser.ID).First(&senderAccountOwner).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("Account not found for user: %s", userUUID), err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Account not found for user",
			})
		}
		logger.Error("Database error while fetching sender account", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Create branch account number by adding "S" to branch code
	branchAccountNumber := "S" + branchCode
	logger.Info(fmt.Sprintf("Looking for branch account with account number: %s", branchAccountNumber))

	// Find the branch account by account number
	var branchAccount accountModel.Account
	if err := a.db.Where("account_number = ? AND is_active = ?", branchAccountNumber, true).
		First(&branchAccount).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("Branch account not found with account number: %s", branchAccountNumber), err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Branch account not found",
			})
		}
		logger.Error("Database error while fetching branch account", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Check if all ledger IDs exist and are valid for debit
	var ledgers []accountModel.AccountLedger
	if err := a.db.Where("id IN ?", req.LedgerIds).Find(&ledgers).Error; err != nil {
		logger.Error("Database error while fetching ledgers", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}
	if len(ledgers) != len(req.LedgerIds) {
		logger.Error("Some ledger IDs not found", nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Some ledger IDs not found",
		})
	}

	// Filter out credits - only keep ledgers that have debit amounts, not credit amounts
	var debitLedgers []accountModel.AccountLedger
	logger.Info(fmt.Sprintf("Starting to filter %d ledgers", len(ledgers)))

	for _, ledger := range ledgers {
		debitVal := "nil"
		creditVal := "nil"

		if ledger.Debit != nil {
			debitVal = fmt.Sprintf("%.2f", *ledger.Debit)
		}
		if ledger.Credit != nil {
			creditVal = fmt.Sprintf("%.2f", *ledger.Credit)
		}

		logger.Info(fmt.Sprintf("Ledger ID %d - Debit: %s, Credit: %s", ledger.ID, debitVal, creditVal))

		if ledger.Debit != nil && *ledger.Debit > 0 && (ledger.Credit == nil || *ledger.Credit == 0) {
			debitLedgers = append(debitLedgers, ledger)
			logger.Info(fmt.Sprintf("Including ledger ID %d as valid debit entry", ledger.ID))
		} else {
			logger.Info(fmt.Sprintf("Filtering out ledger ID %d - Reason: Debit=%s, Credit=%s", ledger.ID, debitVal, creditVal))
		}
	}

	logger.Info(fmt.Sprintf("Filtered result: %d debit ledgers from %d total ledgers", len(debitLedgers), len(ledgers)))

	if len(debitLedgers) == 0 {
		logger.Error("No valid debit ledgers found", nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "No valid debit ledgers found",
		})
	}

	// fetch account ledger table data by debit ledger ids only
	var debitLedgerIds []uint
	for _, ledger := range debitLedgers {
		debitLedgerIds = append(debitLedgerIds, ledger.ID)
	}

	ledgersRecord := accountModel.AccountLedger{}
	if err := a.db.Where("id IN ?", debitLedgerIds).Find(&ledgersRecord).Error; err != nil {
		logger.Error("Database error while fetching debit ledgers", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Calculate total amount from the debit ledgers only
	var totalAmount float64
	for _, ledger := range debitLedgers {
		if ledger.Debit != nil {
			totalAmount += *ledger.Debit
		}
	}

	// Create a new bill record
	BillUuid := BillUuidGenerator()

	// Find the admin's personal account for approver
	var approverAccountID *uint

	// First, find the account owner of the branch account to get the admin ID
	var branchAccountOwner accountModel.AccountOwner
	if err := a.db.Where("account_id = ?", branchAccount.ID).First(&branchAccountOwner).Error; err != nil {
		logger.Error(fmt.Sprintf("Branch account owner not found for account ID: %d", branchAccount.ID), err)
	} else if branchAccountOwner.AdminID != nil {
		// Find the admin's personal account using the admin ID
		var adminAccountOwner accountModel.AccountOwner
		if err := a.db.Preload("Account").
			Where("user_id = ? AND post_office_branch_id IS NULL", *branchAccountOwner.AdminID).
			First(&adminAccountOwner).Error; err == nil {
			// Ensure it's a personal account
			if adminAccountOwner.Account.AccountType == "personal" {
				approverAccountID = &adminAccountOwner.Account.ID
				logger.Info(fmt.Sprintf("Found admin personal account for branch account: %s, admin account ID: %d", branchAccountNumber, adminAccountOwner.Account.ID))
			} else {
				logger.Info(fmt.Sprintf("Admin account found but it's not personal type for branch: %s", branchAccountNumber))
			}
		} else {
			logger.Info(fmt.Sprintf("Admin personal account not found for branch: %s", branchAccountNumber))
		}
	} else {
		logger.Info(fmt.Sprintf("No admin ID found for branch account: %s", branchAccountNumber))
	}

	// Use current user's account as sender and branch account as receiver
	bill := accountModel.PostPaidBill{
		BillUuid:          BillUuid,
		SenderAccountID:   &senderAccountOwner.Account.ID, // Current user's account
		ReceiverAccountID: &branchAccount.ID,              // Branch institutional account
		ApproverAccountID: approverAccountID,              // Admin's personal account if exists
		Amount:            totalAmount,
		Reference:         ledgersRecord.Reference,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	logger.Info(fmt.Sprintf("Creating bill - Sender Account ID: %d, Receiver Account ID: %d, Approver Account ID: %v",
		senderAccountOwner.Account.ID, branchAccount.ID, approverAccountID))

	// Start transaction to create bill and event together
	err := a.db.Transaction(func(tx *gorm.DB) error {
		// Create the bill
		if err := tx.Create(&bill).Error; err != nil {
			return err
		}

		// Create "created" event
		if err := a.CreateBillEvent(tx, bill.ID, senderUser.ID, "created", nil); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		logger.Error("Database error while creating bill and event", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}
	logger.Info(fmt.Sprintf("Created bill with UUID: %s", bill.BillUuid))

	// Update ledgersRecord TABLE with BillID - only for debit ledgers
	for _, ledger := range debitLedgers {
		ledger.BillID = &bill.ID
		if err := a.db.Save(&ledger).Error; err != nil {
			logger.Error("Database error while updating ledger with bill ID", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status":  "error",
				"message": "Internal server error",
			})
		}
	}

	// Prepare detailed account objects for response with account owner information

	// Sender Account (already have senderAccountOwner loaded with Account and User)
	senderAccountObj := fiber.Map{
		"id":             senderAccountOwner.Account.ID,
		"account_number": senderAccountOwner.Account.AccountNumber,
		"account_name":   senderAccountOwner.Account.AccountName,
	}

	// Add account owner info for sender
	if senderAccountOwner.User != nil {
		senderAccountObj["account_owner"] = fiber.Map{
			"user": fiber.Map{
				"id":       senderAccountOwner.User.ID,
				"username": senderAccountOwner.User.Username,
				"uuid":     senderAccountOwner.User.Uuid,
			},
		}
	}

	// Receiver Account - need to load the account owner details
	var receiverAccountOwner accountModel.AccountOwner
	receiverAccountObj := fiber.Map{
		"id":             branchAccount.ID,
		"account_number": branchAccount.AccountNumber,
		"account_name":   branchAccount.AccountName,
	}

	// Load receiver account owner with admin details
	if err := a.db.Preload("Admin").Where("account_id = ?", branchAccount.ID).First(&receiverAccountOwner).Error; err == nil {
		if receiverAccountOwner.Admin != nil {
			receiverAccountObj["account_owner"] = fiber.Map{
				"admin": fiber.Map{
					"id":       receiverAccountOwner.Admin.ID,
					"username": receiverAccountOwner.Admin.Username,
					"uuid":     receiverAccountOwner.Admin.Uuid,
				},
			}
		}
	}

	var approverAccountObj *fiber.Map
	if approverAccountID != nil {
		// Fetch the approver account details with account owner
		var approverAccount accountModel.Account
		if err := a.db.Where("id = ?", *approverAccountID).First(&approverAccount).Error; err == nil {
			approverAccountObj = &fiber.Map{
				"id":             approverAccount.ID,
				"account_number": approverAccount.AccountNumber,
				"account_name":   approverAccount.AccountName,
			}

			// Load approver account owner with user details
			var approverAccountOwner accountModel.AccountOwner
			if err := a.db.Preload("User").Where("account_id = ?", approverAccount.ID).First(&approverAccountOwner).Error; err == nil {
				if approverAccountOwner.User != nil {
					(*approverAccountObj)["account_owner"] = fiber.Map{
						"user": fiber.Map{
							"id":       approverAccountOwner.User.ID,
							"username": approverAccountOwner.User.Username,
							"uuid":     approverAccountOwner.User.Uuid,
						},
					}
				}
			}
		}
	}

	// Create bill response object with status from events
	billStatus := a.GetBillStatus(bill.ID)
	billResponse := fiber.Map{
		"ID":                bill.ID,
		"bill_uuid":         bill.BillUuid,
		"Amount":            bill.Amount,
		"SenderAccountID":   bill.SenderAccountID,
		"ReceiverAccountID": bill.ReceiverAccountID,
		"ApproverAccountID": bill.ApproverAccountID,
		"Reference":         bill.Reference,
		"is_sent":           billStatus["is_sent"],
		"sent_at":           billStatus["sent_at"],
		"is_paid":           billStatus["is_paid"],
		"paid_at":           billStatus["paid_at"],
		"is_approved":       billStatus["is_approved"],
		"approved_at":       billStatus["approved_at"],
		"CreatedAt":         bill.CreatedAt,
		"UpdatedAt":         bill.UpdatedAt,
		"IsDelete":          bill.IsDelete,
		"SenderAccount":     senderAccountObj,
		"ReceiverAccount":   receiverAccountObj,
		"ApproverAccount":   approverAccountObj,
	}

	// Extract processed debit ledger IDs for response
	var processedLedgerIds []uint
	for _, ledger := range debitLedgers {
		processedLedgerIds = append(processedLedgerIds, ledger.ID)
	}

	// now new data create to Post paid bill table

	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": "Bill created successfully",
		"data": fiber.Map{
			"ledger_ids":   processedLedgerIds,
			"total_amount": totalAmount,
			"bill":         billResponse,
		},
	})
}

/*==================================================================================================================
| End Operator Debit Part
===================================================================================================================*/

/*
[==================================================================================================================
| Recipient User Post Paid Bill Table update after payment is_paid = true and update account balance increase
===================================================================================================================
*/
type PostPaidBillPaymentRequest struct {
	//BillUuid string `json:"bill_uuid"`
	BillId uint `json:"bill_id"`
}

func (a *AccountController) PostPaidBillPayment(c *fiber.Ctx) error {
	var req PostPaidBillPaymentRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: fmt.Errorf("Error parsing request body: %v", err).Error(),
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}
	if req.BillId == 0 {
		logger.Error("Bill ID is required", nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: "Bill ID is required",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	// Get user claims from JWT token
	userClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		userLocal := c.Locals("user")
		logger.Error(fmt.Sprintf("Unable to extract user claims from token. Context contains: %+v", userLocal), nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid or missing authentication token",
		})
	}

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

	// Get user's account
	var userAccountOwner accountModel.AccountOwner
	if err := a.db.Preload("Account").Where("user_id = ?", userRecord.ID).First(&userAccountOwner).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error("User account not found", err)
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

	// Fetch the bill record with all necessary checks
	var bill accountModel.PostPaidBill
	if err := a.db.Where("id = ? AND is_delete = ?", req.BillId, 0).First(&bill).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error("Bill not found", err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Bill not found",
			})
		}
		logger.Error("Database error while fetching bill", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Verify that the postmaster is the receiver of this bill
	if bill.ReceiverAccountID == nil || *bill.ReceiverAccountID != userAccountOwner.Account.ID {
		logger.Error(fmt.Sprintf("Unauthorized access to bill ID: %d by user: %s", req.BillId, userUUID), nil)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "error",
			"message": "You can only process payments for bills sent to your account",
		})
	}

	// Check if bill is already paid using events
	isPaid, _ := a.HasBillEvent(bill.ID, "paid")
	if isPaid {
		logger.Error("Bill is already paid", nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Bill is already paid",
		})
	}

	// Check if bill has been sent using events (optional business rule)
	isSent, _ := a.HasBillEvent(bill.ID, "sent")
	if !isSent {
		logger.Error("Bill has not been sent yet", nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Bill has not been sent yet",
		})
	}

	// Start DB transaction
	err := a.db.Transaction(func(tx *gorm.DB) error {
		// Lock sender account
		var senderAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", bill.SenderAccountID).First(&senderAccount).Error; err != nil {
			return err
		}

		// Check if sender has sufficient balance
		if senderAccount.CurrentBalance < bill.Amount {
			return fiber.NewError(fiber.StatusBadRequest, "Insufficient balance in sender's account")
		}

		// Lock receiver account (postmaster's account)
		var receiverAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", bill.ReceiverAccountID).First(&receiverAccount).Error; err != nil {
			return err
		}

		// Update bill timestamp and create "paid" event
		now := time.Now()
		bill.UpdatedAt = now
		if err := tx.Save(&bill).Error; err != nil {
			return err
		}

		// Create "paid" event
		if err := a.CreateBillEvent(tx, bill.ID, userRecord.ID, "paid", nil); err != nil {
			return err
		}

		// Debit from sender account
		senderAccount.CurrentBalance -= bill.Amount
		if err := tx.Save(&senderAccount).Error; err != nil {
			return err
		}

		// Credit to receiver account (postmaster)
		receiverAccount.CurrentBalance += bill.Amount
		if err := tx.Save(&receiverAccount).Error; err != nil {
			return err
		}

		// Create debit ledger entry for sender
		debitLedger := accountModel.AccountLedger{
			BillID:          &bill.ID,
			Debit:           &bill.Amount,
			Credit:          nil,
			Reference:       fmt.Sprintf("Bill Payment Debit - %s", bill.BillUuid),
			ToAccount:       *bill.ReceiverAccountID,
			FromAccount:     bill.SenderAccountID,
			ApprovalStatus:  1,
			ApprovedBy:      nil,
			VerifiedBy:      nil,
			IsAutoVerified:  true,
			TransactionType: "debit",
			CreatedAt:       now,
			UpdatedAt:       &now,
			StatusActive:    1,
			IsDelete:        0,
		}
		// Add current balances before creating
		a.AddCurrentBalancesToLedger(tx, &debitLedger)
		if err := tx.Create(&debitLedger).Error; err != nil {
			return err
		}

		// Create credit ledger entry for receiver (postmaster)
		creditLedger := accountModel.AccountLedger{
			BillID:          &bill.ID,
			Credit:          &bill.Amount,
			Debit:           nil,
			Reference:       fmt.Sprintf("Bill Payment Credit - %s", bill.BillUuid),
			ToAccount:       *bill.ReceiverAccountID,
			FromAccount:     bill.SenderAccountID,
			ApprovalStatus:  1,
			ApprovedBy:      nil,
			VerifiedBy:      nil,
			IsAutoVerified:  true,
			TransactionType: "credit",
			CreatedAt:       now,
			UpdatedAt:       &now,
			StatusActive:    1,
			IsDelete:        0,
		}
		// Add current balances before creating
		a.AddCurrentBalancesToLedger(tx, &creditLedger)
		if err := tx.Create(&creditLedger).Error; err != nil {
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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction failed",
			"error":   err.Error(),
		})
	}

	logger.Info(fmt.Sprintf("Bill ID: %d payment processed successfully by postmaster: %s", req.BillId, userUUID))

	// Get updated bill status
	billStatus := a.GetBillStatus(bill.ID)

	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": "Bill payment processed successfully - sender debited and postmaster credited",
		"data": fiber.Map{
			"bill_id":    bill.ID,
			"bill_uuid":  bill.BillUuid,
			"amount":     bill.Amount,
			"is_paid":    billStatus["is_paid"],
			"paid_at":    billStatus["paid_at"],
			"updated_at": bill.UpdatedAt,
		},
	})
}

func ptrInt(i int) *int {
	return &i
}
func ptrUint(u uint) *uint {
	return &u
}

/*==================================================================================================================
| End Recipient User Post Paid Bill Table update after payment is_paid = true and update account balance increase
===================================================================================================================*/

/*
==================================================================================================================
| approve-bill-amount - dpmg approve bill amount and update account balance increase
===================================================================================================================
*/
type ApproveBillAmountRequest struct {
	BillId uint `json:"bill_id"`
}

func (a *AccountController) ApproveBillAmountDPMG(c *fiber.Ctx) error {
	var req ApproveBillAmountRequest
	if err := c.BodyParser(&req); err != nil || req.BillId == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: "Bill ID is required",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	// Get user claims from JWT token (approver)
	userClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid or missing authentication token",
		})
	}

	// Extract user UUID from claims
	userUUID, ok := userClaims["uuid"].(string)
	if !ok || userUUID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "User UUID not found in token",
		})
	}

	// Find approver user by UUID
	var approverUser user.User
	if err := a.db.Where("uuid = ?", userUUID).First(&approverUser).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Get approver's account
	var approverAccountOwner accountModel.AccountOwner
	if err := a.db.Where("user_id = ?", approverUser.ID).First(&approverAccountOwner).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Approver account not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	err := a.db.Transaction(func(tx *gorm.DB) error {
		// Lock and fetch bill
		var bill accountModel.PostPaidBill
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", req.BillId).First(&bill).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusNotFound, "Bill not found")
			}
			return err
		}
		// Check if bill is already approved using events
		isApproved, _ := a.HasBillEvent(req.BillId, "approved")
		if isApproved {
			return fiber.NewError(fiber.StatusBadRequest, "Bill is already approved")
		}

		amt := bill.Amount

		// Set the approver account ID in the bill
		bill.ApproverAccountID = approverAccountOwner.AccountID

		// Lock approver account (credit destination)
		var approverAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", *approverAccountOwner.AccountID).First(&approverAccount).Error; err != nil {
			return err
		}

		// Lock receiver account (debit destination - postmaster)
		var receiverAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", bill.ReceiverAccountID).First(&receiverAccount).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return fiber.NewError(fiber.StatusNotFound, "Receiver account not found")
			}
			return err
		}

		// Check if receiver account has sufficient balance for the debit
		if receiverAccount.CurrentBalance < amt {
			return fiber.NewError(fiber.StatusBadRequest, "Insufficient balance in receiver's account")
		}

		// Update bill and create "approved" event
		now := time.Now()
		bill.UpdatedAt = now
		if err := tx.Save(&bill).Error; err != nil {
			return err
		}

		// Create "approved" event
		if err := a.CreateBillEvent(tx, bill.ID, approverUser.ID, "approved", nil); err != nil {
			return err
		}

		// Credit approver's account (admin/dpmg gets the credit)
		approverAccount.CurrentBalance += amt
		if err := tx.Save(&approverAccount).Error; err != nil {
			return err
		}

		// Debit receiver's account (postmaster gets debited)
		receiverAccount.CurrentBalance -= amt
		if err := tx.Save(&receiverAccount).Error; err != nil {
			return err
		}

		// Create credit ledger entry for approver
		refCredit := fmt.Sprintf("Bill Approval Credit - %s", bill.BillUuid)
		creditLedger := accountModel.AccountLedger{
			BillID:          &bill.ID,
			Credit:          &amt,
			Reference:       refCredit,
			ToAccount:       *approverAccountOwner.AccountID,
			FromAccount:     bill.ReceiverAccountID,
			ApprovalStatus:  1,
			IsAutoVerified:  true,
			TransactionType: "credit",
			StatusActive:    1,
			IsDelete:        0,
			CreatedAt:       now,
			UpdatedAt:       ptrTime(now),
		}
		if err := tx.Create(&creditLedger).Error; err != nil {
			return err
		}

		// Create debit ledger entry for receiver (postmaster)
		refDebit := fmt.Sprintf("Bill Approval Debit - %s", bill.BillUuid)
		debitLedger := accountModel.AccountLedger{
			BillID:          &bill.ID,
			Debit:           &amt,
			Reference:       refDebit,
			ToAccount:       *approverAccountOwner.AccountID,
			FromAccount:     bill.ReceiverAccountID,
			ApprovalStatus:  1,
			IsAutoVerified:  true,
			TransactionType: "debit",
			StatusActive:    1,
			IsDelete:        0,
			CreatedAt:       now,
			UpdatedAt:       ptrTime(now),
		}
		if err := tx.Create(&debitLedger).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		if f, ok := err.(*fiber.Error); ok {
			return c.Status(f.Code).JSON(fiber.Map{"status": "error", "message": f.Message})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Transaction failed",
			"error":   err.Error(),
		})
	}

	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": "Bill approved - approver credited and receiver debited",
	})
}

/*==================================================================================================================
| End approve-bill-amount - dpmg approve bill amount and update account balance increase
===================================================================================================================*/

/*==================================================================================================================
| Get Account ledger with Debit
===================================================================================================================*/

func (a *AccountController) GetAccountLedgerList(c *fiber.Ctx) error {
	userInfo := c.Locals("user").(map[string]interface{})

	// Extract branch code from JWT claims for account lookup
	branchCode, ok := userInfo["branch_code"].(string)
	if !ok || branchCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Branch code not found in token",
		})
	}

	// Get account list based on role permissions
	var accountIDs []uint

	// Find branch-specific account
	var branchAccount accountModel.Account
	result := a.db.Where("account_number = ?", "S"+branchCode).First(&branchAccount)
	if result.Error == nil {
		// Found branch account
		accountIDs = append(accountIDs, branchAccount.ID)
	} else if result.Error != gorm.ErrRecordNotFound {
		// Database error (not just record not found)
		logger.Error(fmt.Sprintf("Error finding branch account: %v", result.Error), result.Error)
	}

	// Try to find personal account owned by the user (if any)
	userUUID, ok := userInfo["uuid"].(string)
	if ok && userUUID != "" {
		var userAccounts []accountModel.Account
		err := a.db.Joins("JOIN account_owners ON accounts.id = account_owners.account_id").
			Joins("JOIN users ON account_owners.user_id = users.id").
			Where("users.uuid = ?", userUUID).
			Find(&userAccounts).Error
		if err == nil {
			for _, acc := range userAccounts {
				accountIDs = append(accountIDs, acc.ID)
			}
		}
	}

	// Pagination parameters
	page := c.QueryInt("page", 1)         // Default to page 1
	perPage := c.QueryInt("per_page", 20) // Default to 20 per page

	// Calculate offset
	offset := (page - 1) * perPage

	// Get query parameters
	fromDateStr := c.Query("from_date")
	toDateStr := c.Query("to_date")
	entryType := c.Query("entry_type")          // Optional: credit or debit
	fromAccountParam := c.Query("from_account") // Optional account number filter
	toAccountParam := c.Query("to_account")     // Optional account number filter

	// Build base query for ledger entries
	query := a.db.Model(&accountModel.AccountLedger{}).
		Preload("FromAccountRef").
		Preload("ToAccountRef").
		Preload("FromAccountRef.AccountOwner").
		Preload("FromAccountRef.AccountOwner.User").
		Preload("FromAccountRef.AccountOwner.Admin").
		Preload("ToAccountRef.AccountOwner").
		Preload("ToAccountRef.AccountOwner.User").
		Preload("ToAccountRef.AccountOwner.Admin")

	// Filter by accounts that the user has access to (either from_account or to_account)
	if len(accountIDs) > 0 {
		query = query.Where("from_account IN ? OR to_account IN ?", accountIDs, accountIDs)
	} else {
		// No accessible accounts found - return empty result
		return c.JSON(fiber.Map{
			"status": "success",
			"data":   []interface{}{},
			"pagination": fiber.Map{
				"current_page": page,
				"per_page":     perPage,
				"total":        0,
				"total_pages":  0,
				"has_next":     false,
				"has_prev":     false,
			},
		})
	}

	// Date filtering
	if fromDateStr != "" {
		var fromDate time.Time
		var err error

		// Try parsing with timestamp format first (YYYY-MM-DD+HH:MM:SS)
		if fromDate, err = time.Parse("2006-01-02+15:04:05", fromDateStr); err != nil {
			// Try parsing with space separator (YYYY-MM-DD HH:MM:SS) - URL decoded format
			if fromDate, err = time.Parse("2006-01-02 15:04:05", fromDateStr); err != nil {
				// If that fails, try the simple date format (YYYY-MM-DD)
				if fromDate, err = time.Parse("2006-01-02", fromDateStr); err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"status":  "error",
						"message": "Invalid from_date format. Use YYYY-MM-DD, YYYY-MM-DD+HH:MM:SS, or YYYY-MM-DD HH:MM:SS",
					})
				}
			}
		}
		query = query.Where("created_at >= ?", fromDate)
	}
	if toDateStr != "" {
		var toDate time.Time
		var err error

		// Try parsing with timestamp format first (YYYY-MM-DD+HH:MM:SS)
		if toDate, err = time.Parse("2006-01-02+15:04:05", toDateStr); err != nil {
			// Try parsing with space separator (YYYY-MM-DD HH:MM:SS) - URL decoded format
			if toDate, err = time.Parse("2006-01-02 15:04:05", toDateStr); err != nil {
				// If that fails, try the simple date format (YYYY-MM-DD)
				if toDate, err = time.Parse("2006-01-02", toDateStr); err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"status":  "error",
						"message": "Invalid to_date format. Use YYYY-MM-DD, YYYY-MM-DD+HH:MM:SS, or YYYY-MM-DD HH:MM:SS",
					})
				} else {
					// If only date was provided, include the entire day by setting to end of day
					toDate = toDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
				}
			}
		}
		query = query.Where("created_at <= ?", toDate)
	}

	// Entry type filtering (credit or debit from user's perspective)
	if entryType != "" {
		if entryType == "credit" {
			// Money coming into user's accounts (user's account as to_account)
			query = query.Where("to_account IN ?", accountIDs)
		} else if entryType == "debit" {
			// Money going out from user's accounts (user's account as from_account)
			query = query.Where("from_account IN ?", accountIDs)
		}
	}

	// Additional filtering by specific account numbers (from query params)
	if fromAccountParam != "" {
		var fromAccount accountModel.Account
		if err := a.db.Where("account_number = ?", fromAccountParam).First(&fromAccount).Error; err == nil {
			query = query.Where("from_account = ?", fromAccount.ID)
		}
	}
	if toAccountParam != "" {
		var toAccount accountModel.Account
		if err := a.db.Where("account_number = ?", toAccountParam).First(&toAccount).Error; err == nil {
			query = query.Where("to_account = ?", toAccount.ID)
		}
	}

	// Get total count for pagination
	var totalCount int64
	countQuery := query.Session(&gorm.Session{})
	countQuery.Count(&totalCount)

	// Apply pagination and ordering
	var ledgerEntries []accountModel.AccountLedger
	err := query.
		Order("created_at DESC").
		Limit(perPage).
		Offset(offset).
		Find(&ledgerEntries).Error

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch ledger entries",
		})
	}

	// Calculate pagination metadata - using simple division instead of math.Ceil
	totalPages := int((totalCount + int64(perPage) - 1) / int64(perPage))
	hasNext := page < totalPages
	hasPrev := page > 1

	// Transform data for response
	var responseData []fiber.Map
	for _, entry := range ledgerEntries {
		// Calculate the amount (either credit or debit)
		var amount float64
		var transactionType string
		if entry.Credit != nil && *entry.Credit > 0 {
			amount = *entry.Credit
			transactionType = "credit"
		} else if entry.Debit != nil && *entry.Debit > 0 {
			amount = *entry.Debit
			transactionType = "debit"
		}

		entryData := fiber.Map{
			"id":               entry.ID,
			"amount":           amount,
			"reference":        entry.Reference,
			"transaction_type": transactionType,
			"created_at":       entry.CreatedAt,
			"updated_at":       entry.UpdatedAt,
		}

		// Add current balances from ledger entry
		if entry.FromAccountCurrentBalance != nil {
			entryData["from_account_current_balance"] = *entry.FromAccountCurrentBalance
		}
		if entry.ToAccountCurrentBalance != nil {
			entryData["to_account_current_balance"] = *entry.ToAccountCurrentBalance
		}

		// Add from_account info
		if entry.FromAccountRef != nil {
			fromAccountData := fiber.Map{
				"id":             entry.FromAccountRef.ID,
				"account_number": entry.FromAccountRef.AccountNumber,
				"account_name":   entry.FromAccountRef.AccountName,
			}

			// Add account owner info if exists
			if entry.FromAccountRef.AccountOwner != nil {
				ownerInfo := fiber.Map{}
				if entry.FromAccountRef.AccountOwner.User != nil {
					ownerInfo["user"] = fiber.Map{
						"id":       entry.FromAccountRef.AccountOwner.User.ID,
						"username": entry.FromAccountRef.AccountOwner.User.Username,
						"uuid":     entry.FromAccountRef.AccountOwner.User.Uuid,
					}
				}
				if entry.FromAccountRef.AccountOwner.Admin != nil {
					ownerInfo["admin"] = fiber.Map{
						"id":       entry.FromAccountRef.AccountOwner.Admin.ID,
						"username": entry.FromAccountRef.AccountOwner.Admin.Username,
						"uuid":     entry.FromAccountRef.AccountOwner.Admin.Uuid,
					}
				}
				fromAccountData["account_owner"] = ownerInfo
			}

			entryData["from_account"] = fromAccountData
		}

		// Add to_account info
		toAccountData := fiber.Map{
			"id":             entry.ToAccountRef.ID,
			"account_number": entry.ToAccountRef.AccountNumber,
			"account_name":   entry.ToAccountRef.AccountName,
		}

		// Add account owner info if exists
		if entry.ToAccountRef.AccountOwner != nil {
			ownerInfo := fiber.Map{}
			if entry.ToAccountRef.AccountOwner.User != nil {
				ownerInfo["user"] = fiber.Map{
					"id":       entry.ToAccountRef.AccountOwner.User.ID,
					"username": entry.ToAccountRef.AccountOwner.User.Username,
					"uuid":     entry.ToAccountRef.AccountOwner.User.Uuid,
				}
			}
			if entry.ToAccountRef.AccountOwner.Admin != nil {
				ownerInfo["admin"] = fiber.Map{
					"id":       entry.ToAccountRef.AccountOwner.Admin.ID,
					"username": entry.ToAccountRef.AccountOwner.Admin.Username,
					"uuid":     entry.ToAccountRef.AccountOwner.Admin.Uuid,
				}
			}
			toAccountData["account_owner"] = ownerInfo
		}

		entryData["to_account"] = toAccountData

		// Determine if this is a credit or debit from user's perspective
		isCredit := false
		for _, userAccountID := range accountIDs {
			if entry.ToAccount == userAccountID {
				isCredit = true
				break
			}
		}
		entryData["entry_type"] = map[bool]string{true: "credit", false: "debit"}[isCredit]

		responseData = append(responseData, entryData)
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   responseData,
		"pagination": fiber.Map{
			"current_page": page,
			"per_page":     perPage,
			"total":        totalCount,
			"total_pages":  totalPages,
			"has_next":     hasNext,
			"has_prev":     hasPrev,
		},
	})
}

/*==================================================================================================================
| End Get Account ledger with Debit
===================================================================================================================*/

/*
	==================================================================================================================

| Get System Account List by branch code
*/
func (a *AccountController) GetSystemAccountByBranchCode(c *fiber.Ctx) error {
	branchCode := c.Query("branch_code")

	// --- Pagination params (validated) ---
	page := c.QueryInt("page", 1)
	perPage := c.QueryInt("per_page", 20)
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	// --- If branch_code is provided, resolve matching branch IDs ---
	var branchIDs []uint
	if branchCode != "" {
		var branches []user.PostOfficeBranch
		if err := a.db.
			Where("branch_code = ?", branchCode).
			Find(&branches).Error; err != nil {

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status":  "error",
				"message": "Database error (branches)",
			})
		}
		if len(branches) == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Branch not found",
			})
		}
		branchIDs = make([]uint, 0, len(branches))
		for _, b := range branches {
			branchIDs = append(branchIDs, b.ID)
		}
	}

	// --- Base query on AccountOwner with eager-loaded Account ---
	base := a.db.Model(&accountModel.AccountOwner{}).
		Preload("Account").
		Where("account_id IS NOT NULL") // ensure has related Account

	if len(branchIDs) > 0 {
		base = base.Where("post_office_branch_id IN ?", branchIDs)
	}

	// --- Count total (for pagination meta) ---
	var total int64
	if err := base.Count(&total).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to count accounts",
		})
	}

	// --- Fetch paginated rows ---
	var accounts []accountModel.AccountOwner
	if err := base.
		Order("id DESC").
		Limit(perPage).
		Offset(offset).
		Find(&accounts).Error; err != nil {

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch accounts",
		})
	}

	// --- Transform (optional: keep only fields you want) ---
	trimmed := make([]accountModel.AccountOwner, len(accounts))
	for i, acc := range accounts {
		trimmed[i] = accountModel.AccountOwner{
			ID:                 acc.ID,
			UserID:             acc.UserID,
			AccountID:          acc.AccountID,
			PostOfficeBranchID: acc.PostOfficeBranchID,
			Account:            acc.Account, // include details
		}
	}

	// --- Pagination meta ---
	totalPages := int((total + int64(perPage) - 1) / int64(perPage))
	hasNext := page < totalPages
	hasPrev := page > 1

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   trimmed,
		"pagination": fiber.Map{
			"current_page": page,
			"per_page":     perPage,
			"total":        total,
			"total_pages":  totalPages,
			"has_next":     hasNext,
			"has_prev":     hasPrev,
		},
	})
}

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
			Debit:        &req.Debit,
			Credit:       nil,
			Reference:    req.Reference,
			StatusActive: 1,
			IsDelete:     0,
			CreatedAt:    time.Now(),
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

	var accountOwners []accountModel.AccountOwner
	if err := database.DB.Preload("Account").Preload("Org").Preload("User").
		Where("org_id = ?", orgID).Find(&accountOwners).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to retrieve organization accounts",
			"error":   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Organization accounts retrieved successfully",
		"data":    accountOwners,
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
			Debit:        &req.Amount,
			Reference:    req.Reference,
			StatusActive: 1,
			IsDelete:     0,
			CreatedAt:    time.Now(),
			UpdatedAt:    ptrTime(time.Now()),
		}

		creditLedger := accountModel.AccountLedger{
			Credit:       &req.Amount,
			Reference:    req.Reference,
			StatusActive: 1,
			IsDelete:     0,
			CreatedAt:    time.Now(),
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
	req.CreatedAt = now
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

// CreateLedgerEntryWithBalances creates a ledger entry with current account balances
func (a *AccountController) CreateLedgerEntryWithBalances(tx *gorm.DB, params LedgerParams) error {
	// Get current balances before creating the entry
	var fromAccountBalance, toAccountBalance *float64

	// Get ToAccount balance (required)
	var toAccount accountModel.Account
	if err := tx.Where("id = ?", params.ToAccountID).First(&toAccount).Error; err != nil {
		return fmt.Errorf("failed to get ToAccount balance: %w", err)
	}
	toAccountBalance = &toAccount.CurrentBalance

	// Get FromAccount balance if provided (optional)
	if params.FromAccountID != nil {
		var fromAccount accountModel.Account
		if err := tx.Where("id = ?", *params.FromAccountID).First(&fromAccount).Error; err != nil {
			return fmt.Errorf("failed to get FromAccount balance: %w", err)
		}
		fromAccountBalance = &fromAccount.CurrentBalance
	}

	// Create the ledger entry
	ledger := accountModel.AccountLedger{
		BillID:                    params.BillID,
		Reference:                 params.Reference,
		Credit:                    params.Credit,
		Debit:                     params.Debit,
		FromAccountCurrentBalance: fromAccountBalance,
		ToAccountCurrentBalance:   toAccountBalance,
		ChallanNo:                 params.ChallanNo,
		Barcode:                   params.Barcode,
		OrderID:                   params.OrderID,
		ToAccount:                 params.ToAccountID,
		FromAccount:               params.FromAccountID,
		ApprovalStatus:            params.ApprovalStatus,
		ApprovedBy:                params.ApprovedBy,
		VerifiedBy:                params.VerifiedBy,
		IsAutoVerified:            params.IsAutoVerified,
		StatusActive:              params.StatusActive,
		IsDelete:                  params.IsDelete,
		TransactionType:           params.TransactionType,
		ApprovedAt:                params.ApprovedAt,
		VerifiedAt:                params.VerifiedAt,
		CreatedAt:                 time.Now(),
		UpdatedAt:                 ptrTime(time.Now()),
	}

	return tx.Create(&ledger).Error
}

// GetAccountBalance retrieves the current balance for an account by ID
func (a *AccountController) GetAccountBalance(tx *gorm.DB, accountID uint) (float64, error) {
	var account accountModel.Account
	if err := tx.Where("id = ?", accountID).First(&account).Error; err != nil {
		return 0, err
	}
	return account.CurrentBalance, nil
}

// AddCurrentBalancesToLedger adds current account balances to a ledger entry before saving
func (a *AccountController) AddCurrentBalancesToLedger(tx *gorm.DB, ledger *accountModel.AccountLedger) error {
	// Get ToAccount balance (required)
	if toBalance, err := a.GetAccountBalance(tx, ledger.ToAccount); err == nil {
		ledger.ToAccountCurrentBalance = &toBalance
	}

	// Get FromAccount balance if provided (optional)
	if ledger.FromAccount != nil {
		if fromBalance, err := a.GetAccountBalance(tx, *ledger.FromAccount); err == nil {
			ledger.FromAccountCurrentBalance = &fromBalance
		}
	}

	return nil
}

// LedgerParams holds parameters for creating a ledger entry
type LedgerParams struct {
	BillID          *uint
	Reference       string
	Credit          *float64
	Debit           *float64
	ChallanNo       *string
	Barcode         *string
	OrderID         *uint
	ToAccountID     uint
	FromAccountID   *uint
	ApprovalStatus  int
	ApprovedBy      *uint
	VerifiedBy      *uint
	IsAutoVerified  bool
	StatusActive    int
	IsDelete        int
	TransactionType string
	ApprovedAt      *time.Time
	VerifiedAt      *time.Time
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

	// Find AccountOwner by user ID
	var accountOwner accountModel.AccountOwner
	if err := a.db.Preload("Account").Preload("Org").Where("user_id = ?", userRecord.ID).First(&accountOwner).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("AccountOwner not found for user ID: %d", userRecord.ID), err)
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

	// Extract branch_code from claims and find associated PostOfficeBranch
	var postOfficeBranch *user.PostOfficeBranch
	var branchAccountInfo *fiber.Map
	var branchAccountOwner accountModel.AccountOwner

	if branchCode, exists := userClaims["branch_code"].(string); exists && branchCode != "" {
		// Find PostOfficeBranch by branch_code
		var branch user.PostOfficeBranch
		if err := a.db.Where("branch_code = ?", branchCode).First(&branch).Error; err == nil {
			postOfficeBranch = &branch

			// Find branch account information

			if err := a.db.Preload("Account").
				Where("post_office_branch_id = ?", branch.ID).
				First(&branchAccountOwner).Error; err == nil {

				// Successfully found branch account
				branchInfo := fiber.Map{
					"branch_account_number": branchAccountOwner.Account.AccountNumber,
					"branch_account_id":     branchAccountOwner.Account.ID,
					"branch_balance":        branchAccountOwner.Account.CurrentBalance,
					"branch_is_active":      branchAccountOwner.Account.IsActive,
				}
				branchAccountInfo = &branchInfo
			}
		}
	}

	// Prepare response data
	userInfo := fiber.Map{
		"id":             userRecord.ID,
		"uuid":           userRecord.Uuid,
		"username":       userRecord.Username,
		"legal_name":     userRecord.LegalName,
		"phone":          userRecord.Phone,
		"email":          userRecord.Email,
		"phone_verified": userRecord.PhoneVerified,
		"email_verified": userRecord.EmailVerified,
	}
	accountBranchInfo := fiber.Map{}

	// Add branch information if post office branch was found from claims
	if postOfficeBranch != nil {
		accountBranchInfo = fiber.Map{
			"id":                    branchAccountOwner.ID,
			"user_id":               branchAccountOwner.UserID,
			"org_id":                branchAccountOwner.OrgID,
			"admin_id":              branchAccountOwner.AdminID,
			"post_office_branch_id": branchAccountOwner.PostOfficeBranchID,
			"branch_code":           postOfficeBranch.BranchCode,
			"branch_name":           postOfficeBranch.Name,
			"branch_id":             postOfficeBranch.ID,
		}

		// Add branch account information if available
		if branchAccountInfo != nil {
			accountBranchInfo["branch_account_number"] = (*branchAccountInfo)["branch_account_number"]
			accountBranchInfo["branch_account_id"] = (*branchAccountInfo)["branch_account_id"]
			accountBranchInfo["branch_balance"] = (*branchAccountInfo)["branch_balance"]
			accountBranchInfo["branch_is_active"] = (*branchAccountInfo)["branch_is_active"]
		}
	}

	accountInfo := fiber.Map{
		"user_info": userInfo,
		"account_personal": fiber.Map{
			"id":              accountOwner.Account.ID,
			"account_number":  accountOwner.Account.AccountNumber,
			"current_balance": accountOwner.Account.CurrentBalance,
			"account_type":    accountOwner.Account.AccountType,
			"is_active":       accountOwner.Account.IsActive,
			"is_locked":       accountOwner.Account.IsLocked,
			"max_limit":       accountOwner.Account.MaxLimit,
			"balance_type":    accountOwner.Account.BalanceType,
			"currency":        accountOwner.Account.Currency,
			"created_at":      accountOwner.Account.CreatedAt,
			"updated_at":      accountOwner.Account.UpdatedAt,
		},
		"account_branch": accountBranchInfo,
	}

	logger.Success(fmt.Sprintf("Successfully retrieved account information for user: %s", userUUID))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "User account information retrieved successfully",
		"data":    accountInfo,
	})
}

/*==================================================================================================================
| Get PostPaid Bills List with Pagination and Filtering - Admin Route (Only Sent Bills)
===================================================================================================================*/

func (a *AccountController) GetPostPaidBillList(c *fiber.Ctx) error {
	// Extract user claims from JWT token
	userClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		logger.Error("Unable to extract user claims from token", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthorized access",
		})
	}

	// Extract user UUID from claims
	userUUID, ok := userClaims["uuid"].(string)
	if !ok || userUUID == "" {
		logger.Error("User UUID not found in token claims", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "User UUID not found in token",
		})
	}

	// Extract branch code from user claims
	branchCode, ok := userClaims["branch_code"].(string)
	if !ok || branchCode == "" {
		logger.Error("Branch code not found in token claims", nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Branch code not found in token",
		})
	}

	// Get accessible account IDs for the user
	var accessibleAccountIDs []uint

	// Find current user
	var currentUser user.User
	if err := a.db.Where("uuid = ?", userUUID).First(&currentUser).Error; err != nil {
		logger.Error(fmt.Sprintf("User not found with UUID: %s", userUUID), err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "User not found",
		})
	}

	// Find user's personal account
	var userAccountOwner accountModel.AccountOwner
	if err := a.db.Preload("Account").Where("user_id = ?", currentUser.ID).First(&userAccountOwner).Error; err == nil {
		accessibleAccountIDs = append(accessibleAccountIDs, userAccountOwner.Account.ID)
	}

	// Find branch account using "S" + branch code
	branchAccountNumber := "S" + branchCode
	var branchAccount accountModel.Account
	if err := a.db.Where("account_number = ? AND is_active = ?", branchAccountNumber, true).First(&branchAccount).Error; err == nil {
		accessibleAccountIDs = append(accessibleAccountIDs, branchAccount.ID)
	}

	if len(accessibleAccountIDs) == 0 {
		logger.Info(fmt.Sprintf("No accessible accounts found for user: %s", userUUID))
		return c.JSON(fiber.Map{
			"status": "success",
			"data":   []interface{}{},
			"pagination": fiber.Map{
				"current_page": 1,
				"per_page":     20,
				"total":        0,
				"total_pages":  0,
				"has_next":     false,
				"has_prev":     false,
			},
		})
	}

	// Pagination parameters
	page := c.QueryInt("page", 1)         // Default to page 1
	perPage := c.QueryInt("per_page", 20) // Default to 20 per page
	if perPage > 100 {
		perPage = 100 // Max 100 per page
	}

	// Calculate offset
	offset := (page - 1) * perPage

	// Get query parameters for filtering
	fromDateStr := c.Query("from_date")            // Format: YYYY-MM-DD
	toDateStr := c.Query("to_date")                // Format: YYYY-MM-DD
	billStatus := c.Query("bill_status")           // paid, unpaid, approved, unapproved, sent, unsent
	reference := c.Query("reference")              // Filter by reference
	billUuid := c.Query("bill_uuid")               // Filter by bill UUID
	senderAccount := c.Query("sender_account")     // Filter by sender account number
	receiverAccount := c.Query("receiver_account") // Filter by receiver account number

	// Store bill status filter for post-processing (since we now use events)
	var statusFilter string
	if billStatus != "" {
		statusFilter = billStatus
	}

	// Build base query
	query := a.db.Model(&accountModel.PostPaidBill{}).
		Preload("SenderAccount").
		Preload("SenderAccount.AccountOwner").
		Preload("SenderAccount.AccountOwner.User").
		Preload("SenderAccount.AccountOwner.Admin").
		Preload("ReceiverAccount").
		Preload("ReceiverAccount.AccountOwner").
		Preload("ReceiverAccount.AccountOwner.User").
		Preload("ReceiverAccount.AccountOwner.Admin").
		Preload("ApproverAccount").
		Preload("ApproverAccount.AccountOwner").
		Preload("ApproverAccount.AccountOwner.User").
		Preload("ApproverAccount.AccountOwner.Admin")

	// Filter by accessible accounts (bills where user is sender, receiver, or approver)
	query = query.Where("sender_account_id IN ? OR receiver_account_id IN ? OR approver_account_id IN ?",
		accessibleAccountIDs, accessibleAccountIDs, accessibleAccountIDs)

	// Apply filters
	if fromDateStr != "" {
		fromDate, err := time.Parse("2006-01-02", fromDateStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid from_date format. Use YYYY-MM-DD",
			})
		}
		query = query.Where("created_at >= ?", fromDate)
	}

	if toDateStr != "" {
		toDate, err := time.Parse("2006-01-02", toDateStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid to_date format. Use YYYY-MM-DD",
			})
		}
		// Include the entire day by setting to end of day
		toDate = toDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		query = query.Where("created_at <= ?", toDate)
	}

	// Note: Bill status filtering is done after fetching bills
	// since status is determined by events, not database fields

	// Filter by reference
	if reference != "" {
		query = query.Where("reference ILIKE ?", "%"+reference+"%")
	}

	// Filter by bill UUID
	if billUuid != "" {
		query = query.Where("bill_uuid ILIKE ?", "%"+billUuid+"%")
	}

	// Filter by sender account
	if senderAccount != "" {
		var senderAcc accountModel.Account
		if err := a.db.Where("account_number = ?", senderAccount).First(&senderAcc).Error; err == nil {
			query = query.Where("sender_account_id = ?", senderAcc.ID)
		}
	}

	// Filter by receiver account
	if receiverAccount != "" {
		var receiverAcc accountModel.Account
		if err := a.db.Where("account_number = ?", receiverAccount).First(&receiverAcc).Error; err == nil {
			query = query.Where("receiver_account_id = ?", receiverAcc.ID)
		}
	}

	// Filter out soft deleted records
	query = query.Where("is_delete = ?", 0)

	// Filter out inactive bills (only show active bills)
	query = query.Where("is_active = ?", 1)

	// Get total count for pagination
	var totalCount int64
	countQuery := query.Session(&gorm.Session{})
	countQuery.Count(&totalCount)

	// Apply pagination and ordering
	var bills []accountModel.PostPaidBill
	err := query.
		Order("created_at DESC").
		Limit(perPage).
		Offset(offset).
		Find(&bills).Error

	if err != nil {
		logger.Error("Failed to fetch post paid bills", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch post paid bills",
		})
	}

	// Calculate pagination metadata
	totalPages := int((totalCount + int64(perPage) - 1) / int64(perPage))
	hasNext := page < totalPages
	hasPrev := page > 1

	// Transform bills for response
	var responseData []fiber.Map
	for _, bill := range bills {
		billData := a.FormatBillResponse(bill)

		// Apply post-processing status filter if needed
		if statusFilter != "" {
			switch statusFilter {
			case "paid":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "paid"); !hasEvent {
					continue // Skip this bill
				}
			case "unpaid":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "paid"); hasEvent {
					continue // Skip this bill
				}
			case "approved":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "approved"); !hasEvent {
					continue // Skip this bill
				}
			case "unapproved":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "approved"); hasEvent {
					continue // Skip this bill
				}
			case "sent":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "sent"); !hasEvent {
					continue // Skip this bill
				}
			case "unsent":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "sent"); hasEvent {
					continue // Skip this bill
				}
			}
		}

		// Add sender account info
		if bill.SenderAccount != nil {
			senderAccountData := fiber.Map{
				"id":             bill.SenderAccount.ID,
				"account_number": bill.SenderAccount.AccountNumber,
				"account_name":   bill.SenderAccount.AccountName,
			}

			if bill.SenderAccount.AccountOwner != nil {
				ownerInfo := fiber.Map{}
				if bill.SenderAccount.AccountOwner.User != nil {
					ownerInfo["user"] = fiber.Map{
						"id":       bill.SenderAccount.AccountOwner.User.ID,
						"username": bill.SenderAccount.AccountOwner.User.Username,
						"uuid":     bill.SenderAccount.AccountOwner.User.Uuid,
					}
				}
				if bill.SenderAccount.AccountOwner.Admin != nil {
					ownerInfo["admin"] = fiber.Map{
						"id":       bill.SenderAccount.AccountOwner.Admin.ID,
						"username": bill.SenderAccount.AccountOwner.Admin.Username,
						"uuid":     bill.SenderAccount.AccountOwner.Admin.Uuid,
					}
				}
				senderAccountData["account_owner"] = ownerInfo
			}

			billData["SenderAccount"] = senderAccountData
		}

		// Add receiver account info
		if bill.ReceiverAccount != nil {
			receiverAccountData := fiber.Map{
				"id":             bill.ReceiverAccount.ID,
				"account_number": bill.ReceiverAccount.AccountNumber,
				"account_name":   bill.ReceiverAccount.AccountName,
			}

			if bill.ReceiverAccount.AccountOwner != nil {
				ownerInfo := fiber.Map{}
				if bill.ReceiverAccount.AccountOwner.User != nil {
					ownerInfo["user"] = fiber.Map{
						"id":       bill.ReceiverAccount.AccountOwner.User.ID,
						"username": bill.ReceiverAccount.AccountOwner.User.Username,
						"uuid":     bill.ReceiverAccount.AccountOwner.User.Uuid,
					}
				}
				if bill.ReceiverAccount.AccountOwner.Admin != nil {
					ownerInfo["admin"] = fiber.Map{
						"id":       bill.ReceiverAccount.AccountOwner.Admin.ID,
						"username": bill.ReceiverAccount.AccountOwner.Admin.Username,
						"uuid":     bill.ReceiverAccount.AccountOwner.Admin.Uuid,
					}
				}
				receiverAccountData["account_owner"] = ownerInfo
			}

			billData["ReceiverAccount"] = receiverAccountData
		}

		// Add approver account info
		if bill.ApproverAccount != nil {
			approverAccountData := fiber.Map{
				"id":             bill.ApproverAccount.ID,
				"account_number": bill.ApproverAccount.AccountNumber,
				"account_name":   bill.ApproverAccount.AccountName,
			}

			if bill.ApproverAccount.AccountOwner != nil {
				ownerInfo := fiber.Map{}
				if bill.ApproverAccount.AccountOwner.User != nil {
					ownerInfo["user"] = fiber.Map{
						"id":       bill.ApproverAccount.AccountOwner.User.ID,
						"username": bill.ApproverAccount.AccountOwner.User.Username,
						"uuid":     bill.ApproverAccount.AccountOwner.User.Uuid,
					}
				}
				if bill.ApproverAccount.AccountOwner.Admin != nil {
					ownerInfo["admin"] = fiber.Map{
						"id":       bill.ApproverAccount.AccountOwner.Admin.ID,
						"username": bill.ApproverAccount.AccountOwner.Admin.Username,
						"uuid":     bill.ApproverAccount.AccountOwner.Admin.Uuid,
					}
				}
				approverAccountData["account_owner"] = ownerInfo
			}

			billData["ApproverAccount"] = approverAccountData
		}

		responseData = append(responseData, billData)
	}

	logger.Info(fmt.Sprintf("Successfully retrieved %d post paid bills for user: %s", len(responseData), userUUID))

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   responseData,
		"pagination": fiber.Map{
			"current_page": page,
			"per_page":     perPage,
			"total":        totalCount,
			"total_pages":  totalPages,
			"has_next":     hasNext,
			"has_prev":     hasPrev,
		},
	})
}

/*==================================================================================================================
| Get PostPaid Bills List for Operators (Only bills where they are sender) with Pagination and Filtering
===================================================================================================================*/

func (a *AccountController) GetOperatorPostPaidBillList(c *fiber.Ctx) error {
	// Extract user claims from JWT token
	userClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		logger.Error("Unable to extract user claims from token", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthorized access",
		})
	}

	// Extract user UUID from claims
	userUUID, ok := userClaims["uuid"].(string)
	if !ok || userUUID == "" {
		logger.Error("User UUID not found in token claims", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "User UUID not found in token",
		})
	}

	// Find current user
	var currentUser user.User
	if err := a.db.Where("uuid = ?", userUUID).First(&currentUser).Error; err != nil {
		logger.Error(fmt.Sprintf("User not found with UUID: %s", userUUID), err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "User not found",
		})
	}

	// Find user's personal account (operator's account)
	var userAccountOwner accountModel.AccountOwner
	if err := a.db.Preload("Account").Where("user_id = ?", currentUser.ID).First(&userAccountOwner).Error; err != nil {
		logger.Error(fmt.Sprintf("Account not found for user: %s", userUUID), err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "Account not found for user",
		})
	}

	operatorAccountID := userAccountOwner.Account.ID

	// Pagination parameters
	page := c.QueryInt("page", 1)         // Default to page 1
	perPage := c.QueryInt("per_page", 20) // Default to 20 per page
	if perPage > 100 {
		perPage = 100 // Max 100 per page
	}

	// Calculate offset
	offset := (page - 1) * perPage

	// Get query parameters for filtering
	fromDateStr := c.Query("from_date")            // Format: YYYY-MM-DD
	toDateStr := c.Query("to_date")                // Format: YYYY-MM-DD
	billStatus := c.Query("bill_status")           // paid, unpaid, approved, unapproved, sent, unsent
	reference := c.Query("reference")              // Filter by reference
	billUuid := c.Query("bill_uuid")               // Filter by bill UUID
	receiverAccount := c.Query("receiver_account") // Filter by receiver account number

	// Store bill status filter for post-processing (since we now use events)
	var statusFilter string
	if billStatus != "" {
		statusFilter = billStatus
	}

	// Build base query - only bills where operator is the sender
	query := a.db.Model(&accountModel.PostPaidBill{}).
		Preload("SenderAccount").
		Preload("SenderAccount.AccountOwner").
		Preload("SenderAccount.AccountOwner.User").
		Preload("SenderAccount.AccountOwner.Admin").
		Preload("ReceiverAccount").
		Preload("ReceiverAccount.AccountOwner").
		Preload("ReceiverAccount.AccountOwner.User").
		Preload("ReceiverAccount.AccountOwner.Admin").
		Preload("ApproverAccount").
		Preload("ApproverAccount.AccountOwner").
		Preload("ApproverAccount.AccountOwner.User").
		Preload("ApproverAccount.AccountOwner.Admin").
		Where("sender_account_id = ?", operatorAccountID)

	// Apply filters
	if fromDateStr != "" {
		fromDate, err := time.Parse("2006-01-02", fromDateStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid from_date format. Use YYYY-MM-DD",
			})
		}
		query = query.Where("created_at >= ?", fromDate)
	}

	if toDateStr != "" {
		toDate, err := time.Parse("2006-01-02", toDateStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid to_date format. Use YYYY-MM-DD",
			})
		}
		// Include the entire day by setting to end of day
		toDate = toDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		query = query.Where("created_at <= ?", toDate)
	}

	// Note: Bill status filtering is done after fetching bills
	// since status is determined by events, not database fields

	// Filter by reference
	if reference != "" {
		query = query.Where("reference ILIKE ?", "%"+reference+"%")
	}

	// Filter by bill UUID
	if billUuid != "" {
		query = query.Where("bill_uuid ILIKE ?", "%"+billUuid+"%")
	}

	// Filter by receiver account
	if receiverAccount != "" {
		var receiverAcc accountModel.Account
		if err := a.db.Where("account_number = ?", receiverAccount).First(&receiverAcc).Error; err == nil {
			query = query.Where("receiver_account_id = ?", receiverAcc.ID)
		}
	}

	// Filter out soft deleted records
	query = query.Where("is_delete = ?", 0)

	// Get total count for pagination
	var totalCount int64
	countQuery := query.Session(&gorm.Session{})
	countQuery.Count(&totalCount)

	// Apply pagination and ordering
	var bills []accountModel.PostPaidBill
	err := query.
		Order("created_at DESC").
		Limit(perPage).
		Offset(offset).
		Find(&bills).Error

	if err != nil {
		logger.Error("Failed to fetch operator post paid bills", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch post paid bills",
		})
	}

	// Calculate pagination metadata
	totalPages := int((totalCount + int64(perPage) - 1) / int64(perPage))
	hasNext := page < totalPages
	hasPrev := page > 1

	// Transform bills for response
	var responseData []fiber.Map
	for _, bill := range bills {
		billData := a.FormatBillResponse(bill)

		// Apply post-processing status filter if needed
		if statusFilter != "" {
			switch statusFilter {
			case "paid":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "paid"); !hasEvent {
					continue // Skip this bill
				}
			case "unpaid":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "paid"); hasEvent {
					continue // Skip this bill
				}
			case "approved":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "approved"); !hasEvent {
					continue // Skip this bill
				}
			case "unapproved":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "approved"); hasEvent {
					continue // Skip this bill
				}
			case "sent":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "sent"); !hasEvent {
					continue // Skip this bill
				}
			case "unsent":
				if hasEvent, _ := a.HasLatestBillEvent(bill.ID, "sent"); hasEvent {
					continue // Skip this bill
				}
			}
		}

		// Add sender account info
		if bill.SenderAccount != nil {
			senderAccountData := fiber.Map{
				"id":             bill.SenderAccount.ID,
				"account_number": bill.SenderAccount.AccountNumber,
				"account_name":   bill.SenderAccount.AccountName,
			}

			if bill.SenderAccount.AccountOwner != nil {
				ownerInfo := fiber.Map{}
				if bill.SenderAccount.AccountOwner.User != nil {
					ownerInfo["user"] = fiber.Map{
						"id":       bill.SenderAccount.AccountOwner.User.ID,
						"username": bill.SenderAccount.AccountOwner.User.Username,
						"uuid":     bill.SenderAccount.AccountOwner.User.Uuid,
					}
				}
				if bill.SenderAccount.AccountOwner.Admin != nil {
					ownerInfo["admin"] = fiber.Map{
						"id":       bill.SenderAccount.AccountOwner.Admin.ID,
						"username": bill.SenderAccount.AccountOwner.Admin.Username,
						"uuid":     bill.SenderAccount.AccountOwner.Admin.Uuid,
					}
				}
				senderAccountData["account_owner"] = ownerInfo
			}

			billData["SenderAccount"] = senderAccountData
		}

		// Add receiver account info
		if bill.ReceiverAccount != nil {
			receiverAccountData := fiber.Map{
				"id":             bill.ReceiverAccount.ID,
				"account_number": bill.ReceiverAccount.AccountNumber,
				"account_name":   bill.ReceiverAccount.AccountName,
			}

			if bill.ReceiverAccount.AccountOwner != nil {
				ownerInfo := fiber.Map{}
				if bill.ReceiverAccount.AccountOwner.User != nil {
					ownerInfo["user"] = fiber.Map{
						"id":       bill.ReceiverAccount.AccountOwner.User.ID,
						"username": bill.ReceiverAccount.AccountOwner.User.Username,
						"uuid":     bill.ReceiverAccount.AccountOwner.User.Uuid,
					}
				}
				if bill.ReceiverAccount.AccountOwner.Admin != nil {
					ownerInfo["admin"] = fiber.Map{
						"id":       bill.ReceiverAccount.AccountOwner.Admin.ID,
						"username": bill.ReceiverAccount.AccountOwner.Admin.Username,
						"uuid":     bill.ReceiverAccount.AccountOwner.Admin.Uuid,
					}
				}
				receiverAccountData["account_owner"] = ownerInfo
			}

			billData["ReceiverAccount"] = receiverAccountData
		}

		// Add approver account info
		if bill.ApproverAccount != nil {
			approverAccountData := fiber.Map{
				"id":             bill.ApproverAccount.ID,
				"account_number": bill.ApproverAccount.AccountNumber,
				"account_name":   bill.ApproverAccount.AccountName,
			}

			if bill.ApproverAccount.AccountOwner != nil {
				ownerInfo := fiber.Map{}
				if bill.ApproverAccount.AccountOwner.User != nil {
					ownerInfo["user"] = fiber.Map{
						"id":       bill.ApproverAccount.AccountOwner.User.ID,
						"username": bill.ApproverAccount.AccountOwner.User.Username,
						"uuid":     bill.ApproverAccount.AccountOwner.User.Uuid,
					}
				}
				if bill.ApproverAccount.AccountOwner.Admin != nil {
					ownerInfo["admin"] = fiber.Map{
						"id":       bill.ApproverAccount.AccountOwner.Admin.ID,
						"username": bill.ApproverAccount.AccountOwner.Admin.Username,
						"uuid":     bill.ApproverAccount.AccountOwner.Admin.Uuid,
					}
				}
				approverAccountData["account_owner"] = ownerInfo
			}

			billData["ApproverAccount"] = approverAccountData
		}

		responseData = append(responseData, billData)
	}

	logger.Info(fmt.Sprintf("Successfully retrieved %d operator post paid bills for user: %s", len(responseData), userUUID))

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   responseData,
		"pagination": fiber.Map{
			"current_page": page,
			"per_page":     perPage,
			"total":        totalCount,
			"total_pages":  totalPages,
			"has_next":     hasNext,
			"has_prev":     hasPrev,
		},
	})
}

/*==================================================================================================================
| Mark PostPaid Bill as Sent by Operator
===================================================================================================================*/

type MarkBillAsSentRequest struct {
	BillID uint `json:"bill_id" validate:"required"`
}

func (a *AccountController) MarkBillAsSent(c *fiber.Ctx) error {
	var req MarkBillAsSentRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request payload",
			"error":   err.Error(),
		})
	}

	// Validate required fields
	if req.BillID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Bill ID is required",
		})
	}

	// Extract user claims from JWT token
	userClaims, ok := c.Locals("user").(map[string]interface{})
	if !ok {
		logger.Error("Unable to extract user claims from token", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthorized access",
		})
	}

	// Extract user UUID from claims
	userUUID, ok := userClaims["uuid"].(string)
	if !ok || userUUID == "" {
		logger.Error("User UUID not found in token claims", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "User UUID not found in token",
		})
	}

	// Find current user
	var currentUser user.User
	if err := a.db.Where("uuid = ?", userUUID).First(&currentUser).Error; err != nil {
		logger.Error(fmt.Sprintf("User not found with UUID: %s", userUUID), err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "User not found",
		})
	}

	// Find user's account (operator's account)
	var userAccountOwner accountModel.AccountOwner
	if err := a.db.Preload("Account").Where("user_id = ?", currentUser.ID).First(&userAccountOwner).Error; err != nil {
		logger.Error(fmt.Sprintf("Account not found for user: %s", userUUID), err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "Account not found for user",
		})
	}

	operatorAccountID := userAccountOwner.Account.ID

	// Find the bill and verify it belongs to the operator
	var bill accountModel.PostPaidBill
	if err := a.db.Where("id = ? AND is_delete = ?", req.BillID, 0).First(&bill).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("Bill not found with ID: %d", req.BillID), err)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status":  "error",
				"message": "Bill not found",
			})
		}
		logger.Error("Database error while fetching bill", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal server error",
		})
	}

	// Verify that the operator is the sender of this bill
	if bill.SenderAccountID == nil || *bill.SenderAccountID != operatorAccountID {
		logger.Error(fmt.Sprintf("Unauthorized access to bill ID: %d by user: %s", req.BillID, userUUID), nil)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "error",
			"message": "You can only mark bills as sent for bills you created",
		})
	}

	// Check if bill is already marked as sent using events
	isSent, _ := a.HasBillEvent(bill.ID, "sent")
	if isSent {
		logger.Info(fmt.Sprintf("Bill ID: %d is already marked as sent", req.BillID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Bill is already marked as sent",
		})
	}

	// Update the bill and create "sent" event
	now := time.Now()
	bill.UpdatedAt = now
	bill.IsActive = 1

	err := a.db.Transaction(func(tx *gorm.DB) error {
		// Update bill timestamp
		if err := tx.Save(&bill).Error; err != nil {
			return err
		}

		// Create "sent" event
		return a.CreateBillEvent(tx, bill.ID, currentUser.ID, "sent", nil)
	})

	if err != nil {
		logger.Error("Database error while updating bill and creating event", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to update bill status",
		})
	}

	logger.Info(fmt.Sprintf("Bill ID: %d marked as sent by operator: %s", req.BillID, userUUID))

	// Get updated bill status
	billStatus := a.GetBillStatus(bill.ID)

	// Return updated bill information
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Bill marked as sent successfully",
		"data": fiber.Map{
			"bill_id":    bill.ID,
			"bill_uuid":  bill.BillUuid,
			"is_sent":    billStatus["is_sent"],
			"sent_at":    billStatus["sent_at"],
			"updated_at": bill.UpdatedAt,
		},
	})
}
