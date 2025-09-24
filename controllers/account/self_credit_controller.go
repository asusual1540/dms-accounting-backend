package account

import (
	"dms-accounting/database"
	"dms-accounting/logger"
	accountModel "dms-accounting/models/account"
	"dms-accounting/models/user"
	"dms-accounting/types"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SelfCreditController handles self credit operations
type SelfCreditController struct {
	db             *gorm.DB
	loggerInstance *logger.AsyncLogger
}

// NewSelfCreditController creates a new self credit controller
func NewSelfCreditController(db *gorm.DB, loggerInstance *logger.AsyncLogger) *SelfCreditController {
	return &SelfCreditController{db: db, loggerInstance: loggerInstance}
}

// SelfCredit handles self credit balance with document upload
func (s *SelfCreditController) SelfCredit(c *fiber.Ctx) error {
	// Parse form data for file upload
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Invalid multipart form",
			"data":        []interface{}{},
		})
	}

	// Extract form values
	amount := c.FormValue("amount")
	accountNumber := c.FormValue("account_number")
	reference := c.FormValue("reference")

	// Validate required fields
	if accountNumber == "" || amount == "" || reference == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "All fields are required: amount, account_number, reference",
			"data":        []interface{}{},
		})
	}

	// Validate reference length
	if len(reference) < 3 || len(reference) > 255 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Reference must be between 3 and 255 characters",
			"data":        []interface{}{},
		})
	}

	// Validate account number format (assuming it should be 19 digits)
	if len(accountNumber) != 19 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Invalid account number format. Must be 19 digits",
			"data":        []interface{}{},
		})
	}

	// Parse amount
	amountFloat, err := strconv.ParseFloat(amount, 64)
	if err != nil || amountFloat <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Amount must be a positive number",
			"data":        []interface{}{},
		})
	}

	// Validate amount range (max 1,000,000 BDT for safety)
	if amountFloat > 1000000 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Amount cannot exceed 1,000,000 BDT",
			"data":        []interface{}{},
		})
	}

	// Get uploaded files
	files := form.File["document"]
	if len(files) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Document upload is required",
			"data":        []interface{}{},
		})
	}

	// Validate file
	file := files[0]
	if file.Size > 10*1024*1024 { // 10MB limit
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "File size must not exceed 10MB",
			"data":        []interface{}{},
		})
	}

	// Check file extension
	allowedExts := []string{".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx"}
	fileExt := strings.ToLower(filepath.Ext(file.Filename))
	isValidExt := false
	for _, ext := range allowedExts {
		if fileExt == ext {
			isValidExt = true
			break
		}
	}
	if !isValidExt {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 400,
			"message":     "Invalid file type. Allowed types: pdf, jpg, jpeg, png, doc, docx",
			"data":        []interface{}{},
		})
	}

	// Get current user from context
	userInfo := c.Locals("user").(map[string]interface{})
	userUUID, ok := userInfo["uuid"].(string)
	if !ok || userUUID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 401,
			"message":     "Invalid user session - UUID not found",
			"data":        []interface{}{},
		})
	}

	// Find user by UUID to get the user ID
	var currentUser user.User
	if err := database.DB.Where("uuid = ?", userUUID).First(&currentUser).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":      "failed",
			"status_code": 401,
			"message":     "User not found in database",
			"data":        []interface{}{},
		})
	}
	userID := currentUser.ID

	// Start DB transaction
	var savedDocPath string
	var newLedger accountModel.AccountLedger

	err = database.DB.Transaction(func(tx *gorm.DB) error {
		// Find and lock the target account
		var toAccount accountModel.Account
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("account_number = ?", accountNumber).First(&toAccount).Error; err != nil {
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
		if err := tx.Where("reference = ? AND credit IS NOT NULL AND is_delete = 0", reference).First(&existingLedger).Error; err == nil {
			return fiber.NewError(fiber.StatusBadRequest, "Reference already exists for a credit transaction")
		}

		// Check account currency compatibility (assuming BDT for now)
		if toAccount.Currency != "BDT" {
			return fiber.NewError(fiber.StatusBadRequest, "Account currency must be BDT for self credit")
		}

		// Create ledger entry for self-credit (no bill needed)
		ledger := accountModel.AccountLedger{
			BillID:         nil, // No bill for self credit
			RecipientID:    userID,
			SenderID:       userID, // self credit
			OrganizationID: nil,    // No organization for self credit
			Reference:      reference,
			Credit:         &amountFloat,
			IsAutoVerified: true,
			StatusActive:   1,
			IsDelete:       0,
			ToAccount:      &toAccount.ID,
			FromAccount:    &toAccount.ID,
			ApprovalStatus: 1, // auto approved
			ApprovedBy:     &userID,
			ApprovedAt:     ptrTime(time.Now()),
			VerifiedBy:     &userID,
			VerifiedAt:     ptrTime(time.Now()),
			CreatedAt:      ptrTime(time.Now()),
			UpdatedAt:      ptrTime(time.Now()),
		}

		if err := tx.Create(&ledger).Error; err != nil {
			return err
		}
		newLedger = ledger

		// Get username for folder structure
		username, ok := userInfo["username"].(string)
		if !ok || username == "" {
			username = fmt.Sprintf("user_%d", userID) // fallback if username not available
		}

		// Create organized upload directory structure: doc_credit/username/date/
		currentDate := time.Now().Format("2006-01-02") // YYYY-MM-DD format
		uploadDir := fmt.Sprintf("uploads/doc_credit/%s/%s", username, currentDate)
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to create upload directory")
		}

		// Generate unique filename with timestamp
		timestamp := time.Now().Format("150405") // HHMMSS format
		safeFilename := strings.ReplaceAll(file.Filename, " ", "_")
		// Remove any potentially dangerous characters
		safeFilename = strings.ReplaceAll(safeFilename, "..", "_")
		filename := fmt.Sprintf("%s_%s", timestamp, safeFilename)
		filePath := fmt.Sprintf("%s/%s", uploadDir, filename)

		// Save the file
		if err := c.SaveFile(file, filePath); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to save uploaded file")
		}
		savedDocPath = filePath
		fmt.Println("Ledger ID:", ledger.ID)
		// Get the next available ID for ledger_update_documents
		var maxID uint
		tx.Raw("SELECT COALESCE(MAX(id), 0) FROM ledger_update_documents").Scan(&maxID)
		nextID := maxID + 1

		// Create document record with explicit ID
		if err := tx.Exec(
			"INSERT INTO ledger_update_documents (id, account_ledger_id, path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			nextID,
			ledger.ID,
			filePath,
			time.Now(),
			time.Now(),
		).Error; err != nil {
			// Remove the uploaded file if document creation fails
			os.Remove(filePath)
			return err
		}

		// Update account balance
		newBalance := toAccount.CurrentBalance + amountFloat

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
		// Clean up uploaded file on error
		if savedDocPath != "" {
			os.Remove(savedDocPath)
		}

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
	s.loggerInstance.Log(types.LogEntry{
		Method:     "POST",
		URL:        c.OriginalURL(),
		StatusCode: 201,
		CreatedAt:  time.Now(),
	})

	// Return success response
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":      "success",
		"status_code": 201,
		"message":     "Balance credited successfully",
		"data": []fiber.Map{{
			"ledger_id":        newLedger.ID,
			"amount":           amountFloat,
			"reference":        reference,
			"account_number":   accountNumber,
			"document_path":    savedDocPath,
			"transaction_time": newLedger.CreatedAt,
		}},
	})
}
