package auth

import (
	"dms-accounting/database"
	httpServices "dms-accounting/httpServices/sso"
	"dms-accounting/logger"
	sso "dms-accounting/middleware"
	"dms-accounting/models/account"
	"dms-accounting/models/user"
	"dms-accounting/types"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type AuthController struct {
	db             *gorm.DB
	httpService    *httpServices.SSOClient
	loggerInstance *logger.AsyncLogger
}

func NewAuthController(service *httpServices.SSOClient, db *gorm.DB, async_logger *logger.AsyncLogger) *AuthController {
	return &AuthController{httpService: service, db: db, loggerInstance: async_logger}
}

// Helper function to set secure cookies based on environment
func (h *AuthController) setSecureCookie(c *fiber.Ctx, name, value string, maxAge int) {
	isProduction := os.Getenv("APP_ENV") == "production"

	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		HTTPOnly: false,
		Secure:   isProduction, // Only secure in production (HTTPS)
		SameSite: "Strict",
		MaxAge:   maxAge,
		Path:     "/",
	})
}

func (h *AuthController) Register(c *fiber.Ctx) error {
	// Parse the request body as JSON
	var req types.RegisterUserRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		response := types.ErrorResponse{
			Message: fmt.Sprintf("Error parsing request body: %v", err),
			Status:  fiber.StatusBadRequest,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Get the access token from Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		logger.Error("Authorization header missing", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrorResponse{
			Message: "Authorization token required",
			Status:  fiber.StatusUnauthorized,
		})
	}

	// Extract Bearer token
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		logger.Error("Invalid authorization header format", nil)
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrorResponse{
			Message: "Invalid authorization header format",
			Status:  fiber.StatusUnauthorized,
		})
	}

	accessToken := tokenParts[1] // Extract the actual token

	// Validate request
	if validationErr := req.Validate(); validationErr != "" {
		logger.Error(validationErr, nil)
		response := types.ErrorResponse{
			Message: validationErr,
			Status:  fiber.StatusBadRequest,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	// Make call to external API through the service
	registerResponse, err := h.httpService.RequestRegisterUser(types.RegisterUserRequest{
		PhoneNumber: req.PhoneNumber,
		Token:       req.Token,
		Password:    req.Password,
		Username:    req.Username,
		Access:      accessToken, // Pass the extracted access token
	})
	// fmt.Println("Register Response: ", registerResponse)
	if err != nil {
		logger.Error("Failed to login user", err)
		return c.Status(fiber.StatusBadGateway).JSON(types.ErrorResponse{
			Message: "Failed to login user",
			Status:  fiber.StatusBadGateway,
		})
	}

	currentTime := time.Now().Format("2006-01-02 03:04:05 PM")

	// If registration was successful, create user in local database
	if registerResponse.Status == "success" && registerResponse.User.UUID != "" {
		// Create user in local database
		newUser := user.User{
			Uuid:          registerResponse.User.UUID,
			Username:      registerResponse.User.Username,
			Phone:         registerResponse.User.PhoneNumber,
			PhoneVerified: false, // Set to false initially as SMS is sent for verification
			EmailVerified: false,
			LegalName:     "",                 // Set to empty string if null in response
			Avatar:        "",                 // Set to empty string if null in response
			Nonce:         0,                  // Default value
			Permissions:   user.StringSlice{}, // Empty permissions array
		}

		// Handle nullable fields
		if registerResponse.User.Email != nil && *registerResponse.User.Email != "" {
			newUser.Email = registerResponse.User.Email
		}
		// Email remains nil if not provided or empty
		if registerResponse.User.LegalName != nil {
			newUser.LegalName = *registerResponse.User.LegalName
		}
		if registerResponse.User.Avatar != nil {
			newUser.Avatar = *registerResponse.User.Avatar
		}

		// Create user in database
		if err := database.DB.Create(&newUser).Error; err != nil {
			logger.Error("Failed to create user in local database", err)
			// Note: We still return success since external registration succeeded
			// This is just a local database sync issue
		} else {
			logger.Success("User created in local database successfully. UUID: " + newUser.Uuid)
		}
	}

	logEntry := types.LogEntry{
		Method:          c.Method(),
		URL:             c.OriginalURL(),
		RequestBody:     string(c.Body()),
		ResponseBody:    string(c.Response().Body()),
		RequestHeaders:  string(c.Request().Header.Header()),
		ResponseHeaders: string(c.Response().Header.Header()),
		StatusCode:      c.Response().StatusCode(),
		CreatedAt:       time.Now(),
	}
	h.loggerInstance.Log(logEntry)

	logger.Success("User registered in successfully." + " at " + currentTime)
	return c.Status(fiber.StatusOK).JSON(registerResponse)
	// // Start Transaction
	// tx := database.DB.Begin()

	// // Create user
	// createUser := models.User{
	// 	Uuid:          uuid.NewString(),
	// 	Username:      req.Username,
	// 	LegalName:     req.LegalName,
	// 	Phone:         req.Phone,
	// 	PhoneVerified: false,
	// 	Email:         req.Email,
	// 	EmailVerified: false,
	// 	Avatar:        "", // or req.Avatar if available
	// 	Nonce:         0,  // default value, update as needed
	// 	CreatedBy:     nil,
	// 	ApprovedBy:    nil,
	// 	Permissions:   []string{},
	// }

	// if err := tx.Create(&createUser).Error; err != nil {
	// 	tx.Rollback()
	// 	logger.Error("Failed to create user", err)
	// 	return c.Status(fiber.StatusInternalServerError).JSON(types.ApiResponse{
	// 		Message: fmt.Sprintf("Failed to create user: %v", err),
	// 		Status:  fiber.StatusInternalServerError,
	// 	})
	// }

	// tx.Commit()

}

// 19-digit unique account number: "10" + epoch ms (13) + 4 random = 19
func generateAccountNumber() string {
	ms := time.Now().UnixMilli() // 13 digits
	r := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(10000)
	return fmt.Sprintf("10%d%04d", ms, r)
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

// Create a fresh personal Account with unique AccountNumber (retry on conflict)
func ensurePersonalAccount(tx *gorm.DB) (*account.Account, error) {
	const maxRetries = 3 // Reduced from 5 - should be rare with timestamp-based generation

	for attempt := 0; attempt < maxRetries; attempt++ {
		accountNumber := generateAccountNumber()
		logger.Info(fmt.Sprintf("Attempting to create account with number: %s (attempt %d/%d)", accountNumber, attempt+1, maxRetries))

		acc := account.Account{
			AccountNumber:   accountNumber,
			CurrentBalance:  0.00,
			AccountType:     "personal",
			IsActive:        true,
			IsLocked:        false,
			CreatedAt:       ptrTime(time.Now()),
			UpdatedAt:       ptrTime(time.Now()),
			MaxLimit:        0.00,
			BalanceType:     "",
			Currency:        "BDT",
			IsSystemAccount: false, // Personal accounts are not system accounts
		}

		res := tx.
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "account_number"}}, // unique column
				DoNothing: true,
			}).
			Create(&acc)

		if res.Error != nil {
			logger.Error(fmt.Sprintf("Failed to create account (attempt %d): %v", attempt+1, res.Error), res.Error)
			return nil, res.Error
		}

		if res.RowsAffected == 1 {
			logger.Success(fmt.Sprintf("Successfully created account with ID: %d, AccountNumber: %s", acc.ID, acc.AccountNumber))
			return &acc, nil // created successfully
		}

		// conflict occurred → retry with a new number
		logger.Warning(fmt.Sprintf("Account number conflict occurred for %s, retrying with new number...", accountNumber))
		time.Sleep(time.Millisecond * 10) // Small delay to ensure different timestamp
	}

	err := fmt.Errorf("failed to create unique Account after %d retries", maxRetries)
	logger.Error("Account creation failed after all retries", err)
	return nil, err
}

// EnsureUserAccount: user_id এর জন্য UserAccount থাকলে ফেরত দেয়,
// না থাকলে নতুন Account বানিয়ে map করে দেয়।
func EnsureUserAccount(tx *gorm.DB, userID uint) (*account.AccountOwner, error) {
	// For backward compatibility, we'll use org_id = 1 as default
	// This should be updated based on your business logic
	defaultOrgID := uint(1)
	return EnsureAccountOwner(tx, userID, defaultOrgID)
}

// EnsureAccountOwner: user_id এর জন্য AccountOwner থাকলে ফেরত দেয়,
// না থাকলে নতুন Account বানিয়ে map করে দেয়।
func EnsureAccountOwner(tx *gorm.DB, userID uint, orgID uint) (*account.AccountOwner, error) {
	var accountOwner account.AccountOwner

	// Check if AccountOwner already exists
	if err := tx.Where("user_id = ? AND org_id = ?", userID, orgID).First(&accountOwner).Error; err == nil {
		logger.Info(fmt.Sprintf("Found existing AccountOwner for user_id: %d, org_id: %d", userID, orgID))
		return &accountOwner, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Error(fmt.Sprintf("Error querying AccountOwner for user_id %d, org_id %d", userID, orgID), err)
		return nil, err
	}

	logger.Info(fmt.Sprintf("No existing AccountOwner found for user_id: %d, org_id: %d, creating new one", userID, orgID))

	// Create a fresh Account
	acc, err := ensurePersonalAccount(tx)
	if err != nil {
		return nil, fmt.Errorf("ensurePersonalAccount failed: %w", err)
	}

	// Create AccountOwner - simple insert since we already checked it doesn't exist
	accountOwner = account.AccountOwner{
		UserID:    &userID,
		AccountID: &acc.ID,
		OrgID:     &orgID,
	}

	if err := tx.Create(&accountOwner).Error; err != nil {
		logger.Error(fmt.Sprintf("Failed to create AccountOwner for user_id %d, org_id %d", userID, orgID), err)
		return nil, err
	}

	logger.Success(fmt.Sprintf("Successfully created AccountOwner: user_id=%d, account_id=%d, org_id=%d", *accountOwner.UserID, *accountOwner.AccountID, *accountOwner.OrgID))
	return &accountOwner, nil
}

// ---- Full Login ------------------------------------------------------------
func (h *AuthController) Login(c *fiber.Ctx) error {
	// 1) Parse & validate
	var req types.LoginRequest
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

	// 2) SSO call
	loginResp, err := h.httpService.RequestLoginUser(types.LoginRequest{
		PhoneNumber: req.PhoneNumber,
		Redirect:    req.Redirect,
		Password:    req.Password,
	})
	if err != nil {
		logger.Error("Failed to login user (external)", err)
		code := fiber.StatusBadGateway
		msg := err.Error()
		l := strings.ToLower(msg)
		if strings.Contains(l, "http 400") || strings.Contains(l, "http 422") {
			code = fiber.StatusBadRequest
		}
		if strings.Contains(l, "http 401") || strings.Contains(l, "invalid credential") {
			code = fiber.StatusUnauthorized
		}
		return c.Status(code).JSON(types.ApiResponse{
			Message: msg,
			Status:  code,
			Data:    nil,
		})
	}
	if loginResp == nil || loginResp.Status != "success" || strings.TrimSpace(loginResp.Data.UUID) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ApiResponse{
			Message: "Invalid credentials",
			Status:  fiber.StatusUnauthorized,
			Data:    loginResp,
		})
	}

	uid := strings.TrimSpace(loginResp.Data.UUID)
	nowStr := time.Now().Format("2006-01-02 03:04:05 PM")

	// 3) Upsert user + EnsureUserAccount in one transaction
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var u user.User

		// (A) Try by UUID (fast path: update)
		if err := tx.Where("uuid = ?", uid).First(&u).Error; err == nil {
			u.Username = loginResp.Data.Username
			u.Phone = loginResp.Data.Phone
			u.PhoneVerified = loginResp.Data.PhoneVerified
			u.EmailVerified = loginResp.Data.EmailVerified
			u.Avatar = loginResp.Data.Avatar
			u.Nonce = loginResp.Data.Nonce
			u.Permissions = user.StringSlice(loginResp.Data.Permissions)
			if loginResp.Data.LegalName != nil {
				u.LegalName = *loginResp.Data.LegalName
			}
			if loginResp.Data.Email != nil && *loginResp.Data.Email != "" {
				u.Email = loginResp.Data.Email // pointer ok
			}

			// Handle branch_code if provided
			if loginResp.Data.BranchCode != nil && *loginResp.Data.BranchCode != "" {
				var postOfficeBranch user.PostOfficeBranch
				if err := tx.Where("branch_code = ?", *loginResp.Data.BranchCode).First(&postOfficeBranch).Error; err == nil {
					u.PostOfficeBranchID = &postOfficeBranch.ID
					logger.Info(fmt.Sprintf("Found PostOfficeBranch with code %s, assigned to user %s", *loginResp.Data.BranchCode, uid))
				} else if errors.Is(err, gorm.ErrRecordNotFound) {
					logger.Warning(fmt.Sprintf("PostOfficeBranch with code %s not found for user %s", *loginResp.Data.BranchCode, uid))
				} else {
					logger.Error(fmt.Sprintf("Error finding PostOfficeBranch with code %s", *loginResp.Data.BranchCode), err)
				}

				// Check if user has post-master or postmaster permissions
				hasPostMasterPermission := false
				for _, permission := range loginResp.Data.Permissions {
					if strings.Contains(strings.ToLower(permission), "post-master") || strings.Contains(strings.ToLower(permission), "postmaster") {
						hasPostMasterPermission = true
						break
					}
				}

				if hasPostMasterPermission {
					// Create system account with S + BranchCode
					systemAccountNumber := "S" + *loginResp.Data.BranchCode
					logger.Info(fmt.Sprintf("User %s has post-master permission, creating/finding system account %s", uid, systemAccountNumber))

					var systemAccount account.Account
					// Try to find existing system account
					if err := tx.Where("account_number = ?", systemAccountNumber).First(&systemAccount).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							// Create new system account
							systemAccount = account.Account{
								AccountNumber:   systemAccountNumber,
								CurrentBalance:  0.00,
								AccountType:     "system",
								IsActive:        true,
								IsLocked:        false,
								CreatedAt:       ptrTime(time.Now()),
								UpdatedAt:       ptrTime(time.Now()),
								MaxLimit:        0.00,
								BalanceType:     "system",
								Currency:        "BDT",
								IsSystemAccount: true,
							}
							if err := tx.Create(&systemAccount).Error; err != nil {
								logger.Error(fmt.Sprintf("Failed to create system account %s", systemAccountNumber), err)
							} else {
								logger.Success(fmt.Sprintf("Created system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
							}
						} else {
							logger.Error(fmt.Sprintf("Error finding system account %s", systemAccountNumber), err)
						}
					} else {
						logger.Info(fmt.Sprintf("Found existing system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
					}

					// Find or create AccountOwner for the system account
					if systemAccount.ID > 0 {
						var systemAccountOwner account.AccountOwner
						if err := tx.Where("account_id = ?", systemAccount.ID).First(&systemAccountOwner).Error; err != nil {
							if errors.Is(err, gorm.ErrRecordNotFound) {
								// Create new AccountOwner
								defaultOrgID := uint(1) // Use default org ID
								systemAccountOwner = account.AccountOwner{
									UserID:             &u.ID,
									AccountID:          &systemAccount.ID,
									OrgID:              &defaultOrgID,
									PostOfficeBranchID: u.PostOfficeBranchID,
								}
								if err := tx.Create(&systemAccountOwner).Error; err != nil {
									logger.Error(fmt.Sprintf("Failed to create AccountOwner for system account %s", systemAccountNumber), err)
								} else {
									logger.Success(fmt.Sprintf("Created AccountOwner for system account %s, assigned to user %s", systemAccountNumber, uid))
								}
							} else {
								logger.Error(fmt.Sprintf("Error finding AccountOwner for system account %s", systemAccountNumber), err)
							}
						} else {
							// AccountOwner exists, check if UserID is empty and assign if needed
							if systemAccountOwner.UserID == nil {
								systemAccountOwner.UserID = &u.ID
								systemAccountOwner.PostOfficeBranchID = u.PostOfficeBranchID
								if err := tx.Save(&systemAccountOwner).Error; err != nil {
									logger.Error(fmt.Sprintf("Failed to assign user to AccountOwner for system account %s", systemAccountNumber), err)
								} else {
									logger.Success(fmt.Sprintf("Assigned user %s to existing AccountOwner for system account %s", uid, systemAccountNumber))
								}
							} else {
								logger.Info(fmt.Sprintf("System account %s already has a UserID assigned", systemAccountNumber))
							}
						}
					}
				}
			}

			if err := tx.Save(&u).Error; err != nil {
				return fmt.Errorf("update user by uuid failed: %w", err)
			}
			if _, err := EnsureUserAccount(tx, u.ID); err != nil {
				return fmt.Errorf("ensure user-account failed: %w", err)
			}
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("query user by uuid failed: %w", err)
		}

		// (B) Not found by UUID → try by Phone (merge into existing record)
		if strings.TrimSpace(loginResp.Data.Phone) != "" {
			if err := tx.Where("phone = ?", loginResp.Data.Phone).First(&u).Error; err == nil {
				// Merge: attach SSO uuid + update fields
				u.Uuid = uid
				u.Username = loginResp.Data.Username
				u.PhoneVerified = loginResp.Data.PhoneVerified
				u.EmailVerified = loginResp.Data.EmailVerified
				u.Avatar = loginResp.Data.Avatar
				u.Nonce = loginResp.Data.Nonce
				u.Permissions = user.StringSlice(loginResp.Data.Permissions)
				if loginResp.Data.LegalName != nil {
					u.LegalName = *loginResp.Data.LegalName
				}
				if loginResp.Data.Email != nil && *loginResp.Data.Email != "" {
					u.Email = loginResp.Data.Email
				}

				// Handle branch_code if provided
				if loginResp.Data.BranchCode != nil && *loginResp.Data.BranchCode != "" {
					var postOfficeBranch user.PostOfficeBranch
					if err := tx.Where("branch_code = ?", *loginResp.Data.BranchCode).First(&postOfficeBranch).Error; err == nil {
						u.PostOfficeBranchID = &postOfficeBranch.ID
						logger.Info(fmt.Sprintf("Found PostOfficeBranch with code %s, assigned to user %s", *loginResp.Data.BranchCode, uid))
					} else if errors.Is(err, gorm.ErrRecordNotFound) {
						logger.Warning(fmt.Sprintf("PostOfficeBranch with code %s not found for user %s", *loginResp.Data.BranchCode, uid))
					} else {
						logger.Error(fmt.Sprintf("Error finding PostOfficeBranch with code %s", *loginResp.Data.BranchCode), err)
					}

					// Check if user has post-master or postmaster permissions
					hasPostMasterPermission := false
					for _, permission := range loginResp.Data.Permissions {
						if strings.Contains(strings.ToLower(permission), "post-master") || strings.Contains(strings.ToLower(permission), "postmaster") {
							hasPostMasterPermission = true
							break
						}
					}

					if hasPostMasterPermission {
						// Create system account with S + BranchCode
						systemAccountNumber := "S" + *loginResp.Data.BranchCode
						logger.Info(fmt.Sprintf("User %s has post-master permission, creating/finding system account %s", uid, systemAccountNumber))

						var systemAccount account.Account
						// Try to find existing system account
						if err := tx.Where("account_number = ?", systemAccountNumber).First(&systemAccount).Error; err != nil {
							if errors.Is(err, gorm.ErrRecordNotFound) {
								// Create new system account
								systemAccount = account.Account{
									AccountNumber:   systemAccountNumber,
									CurrentBalance:  0.00,
									AccountType:     "system",
									IsActive:        true,
									IsLocked:        false,
									CreatedAt:       ptrTime(time.Now()),
									UpdatedAt:       ptrTime(time.Now()),
									MaxLimit:        0.00,
									BalanceType:     "system",
									Currency:        "BDT",
									IsSystemAccount: true,
								}
								if err := tx.Create(&systemAccount).Error; err != nil {
									logger.Error(fmt.Sprintf("Failed to create system account %s", systemAccountNumber), err)
								} else {
									logger.Success(fmt.Sprintf("Created system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
								}
							} else {
								logger.Error(fmt.Sprintf("Error finding system account %s", systemAccountNumber), err)
							}
						} else {
							logger.Info(fmt.Sprintf("Found existing system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
						}

						// Find or create AccountOwner for the system account
						if systemAccount.ID > 0 {
							var systemAccountOwner account.AccountOwner
							if err := tx.Where("account_id = ?", systemAccount.ID).First(&systemAccountOwner).Error; err != nil {
								if errors.Is(err, gorm.ErrRecordNotFound) {
									// Create new AccountOwner
									defaultOrgID := uint(1) // Use default org ID
									systemAccountOwner = account.AccountOwner{
										UserID:             &u.ID,
										AccountID:          &systemAccount.ID,
										OrgID:              &defaultOrgID,
										PostOfficeBranchID: u.PostOfficeBranchID,
									}
									if err := tx.Create(&systemAccountOwner).Error; err != nil {
										logger.Error(fmt.Sprintf("Failed to create AccountOwner for system account %s", systemAccountNumber), err)
									} else {
										logger.Success(fmt.Sprintf("Created AccountOwner for system account %s, assigned to user %s", systemAccountNumber, uid))
									}
								} else {
									logger.Error(fmt.Sprintf("Error finding AccountOwner for system account %s", systemAccountNumber), err)
								}
							} else {
								// AccountOwner exists, check if UserID is empty and assign if needed
								if systemAccountOwner.UserID == nil {
									systemAccountOwner.UserID = &u.ID
									systemAccountOwner.PostOfficeBranchID = u.PostOfficeBranchID
									if err := tx.Save(&systemAccountOwner).Error; err != nil {
										logger.Error(fmt.Sprintf("Failed to assign user to AccountOwner for system account %s", systemAccountNumber), err)
									} else {
										logger.Success(fmt.Sprintf("Assigned user %s to existing AccountOwner for system account %s", uid, systemAccountNumber))
									}
								} else {
									logger.Info(fmt.Sprintf("System account %s already has a UserID assigned", systemAccountNumber))
								}
							}
						}
					}
				}

				if err := tx.Save(&u).Error; err != nil {
					return fmt.Errorf("merge user by phone failed: %w", err)
				}
				if _, err := EnsureUserAccount(tx, u.ID); err != nil {
					return fmt.Errorf("ensure user-account failed: %w", err)
				}
				return nil
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("query user by phone failed: %w", err)
			}
		}

		// (C) Create new user (no uuid/phone match)
		nu := user.User{
			Uuid:          uid,
			Username:      loginResp.Data.Username,
			Phone:         loginResp.Data.Phone,
			PhoneVerified: loginResp.Data.PhoneVerified,
			Email:         loginResp.Data.Email, // pointer allowed (may be nil)
			EmailVerified: loginResp.Data.EmailVerified,
			Avatar:        loginResp.Data.Avatar,
			Nonce:         loginResp.Data.Nonce,
			Permissions:   user.StringSlice(loginResp.Data.Permissions),
		}
		if loginResp.Data.LegalName != nil {
			nu.LegalName = *loginResp.Data.LegalName
		}

		// Handle branch_code if provided
		if loginResp.Data.BranchCode != nil && *loginResp.Data.BranchCode != "" {
			var postOfficeBranch user.PostOfficeBranch
			if err := tx.Where("branch_code = ?", *loginResp.Data.BranchCode).First(&postOfficeBranch).Error; err == nil {
				nu.PostOfficeBranchID = &postOfficeBranch.ID
				logger.Info(fmt.Sprintf("Found PostOfficeBranch with code %s, assigned to new user %s", *loginResp.Data.BranchCode, uid))
			} else if errors.Is(err, gorm.ErrRecordNotFound) {
				logger.Warning(fmt.Sprintf("PostOfficeBranch with code %s not found for new user %s", *loginResp.Data.BranchCode, uid))
			} else {
				logger.Error(fmt.Sprintf("Error finding PostOfficeBranch with code %s for new user", *loginResp.Data.BranchCode), err)
			}
		}

		// Create with "ON CONFLICT DO NOTHING" to swallow rare races; then fetch by uuid
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&nu).Error; err != nil {
			return fmt.Errorf("create user failed: %w", err)
		}
		// Fetch back (covers DoNothing case)
		if err := tx.Where("uuid = ?", uid).First(&nu).Error; err != nil {
			return fmt.Errorf("fetch created user failed: %w", err)
		}

		// Handle post-master system account creation after user is created and has ID
		if loginResp.Data.BranchCode != nil && *loginResp.Data.BranchCode != "" {
			// Check if user has post-master or postmaster permissions
			hasPostMasterPermission := false
			for _, permission := range loginResp.Data.Permissions {
				if strings.Contains(strings.ToLower(permission), "post-master") || strings.Contains(strings.ToLower(permission), "postmaster") {
					hasPostMasterPermission = true
					break
				}
			}

			if hasPostMasterPermission {
				// Create system account with S + BranchCode
				systemAccountNumber := "S" + *loginResp.Data.BranchCode
				logger.Info(fmt.Sprintf("New user %s has post-master permission, creating/finding system account %s", uid, systemAccountNumber))

				var systemAccount account.Account
				// Try to find existing system account
				if err := tx.Where("account_number = ?", systemAccountNumber).First(&systemAccount).Error; err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						// Create new system account
						systemAccount = account.Account{
							AccountNumber:   systemAccountNumber,
							CurrentBalance:  0.00,
							AccountType:     "system",
							IsActive:        true,
							IsLocked:        false,
							CreatedAt:       ptrTime(time.Now()),
							UpdatedAt:       ptrTime(time.Now()),
							MaxLimit:        0.00,
							BalanceType:     "system",
							Currency:        "BDT",
							IsSystemAccount: true,
						}
						if err := tx.Create(&systemAccount).Error; err != nil {
							logger.Error(fmt.Sprintf("Failed to create system account %s", systemAccountNumber), err)
						} else {
							logger.Success(fmt.Sprintf("Created system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
						}
					} else {
						logger.Error(fmt.Sprintf("Error finding system account %s", systemAccountNumber), err)
					}
				} else {
					logger.Info(fmt.Sprintf("Found existing system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
				}

				// Find or create AccountOwner for the system account
				if systemAccount.ID > 0 {
					var systemAccountOwner account.AccountOwner
					if err := tx.Where("account_id = ?", systemAccount.ID).First(&systemAccountOwner).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							// Create new AccountOwner
							defaultOrgID := uint(1) // Use default org ID
							systemAccountOwner = account.AccountOwner{
								UserID:             &nu.ID,
								AccountID:          &systemAccount.ID,
								OrgID:              &defaultOrgID,
								PostOfficeBranchID: nu.PostOfficeBranchID,
							}
							if err := tx.Create(&systemAccountOwner).Error; err != nil {
								logger.Error(fmt.Sprintf("Failed to create AccountOwner for system account %s", systemAccountNumber), err)
							} else {
								logger.Success(fmt.Sprintf("Created AccountOwner for system account %s, assigned to new user %s", systemAccountNumber, uid))
							}
						} else {
							logger.Error(fmt.Sprintf("Error finding AccountOwner for system account %s", systemAccountNumber), err)
						}
					} else {
						// AccountOwner exists, check if UserID is empty and assign if needed
						if systemAccountOwner.UserID == nil {
							systemAccountOwner.UserID = &nu.ID
							systemAccountOwner.PostOfficeBranchID = nu.PostOfficeBranchID
							if err := tx.Save(&systemAccountOwner).Error; err != nil {
								logger.Error(fmt.Sprintf("Failed to assign new user to AccountOwner for system account %s", systemAccountNumber), err)
							} else {
								logger.Success(fmt.Sprintf("Assigned new user %s to existing AccountOwner for system account %s", uid, systemAccountNumber))
							}
						} else {
							logger.Info(fmt.Sprintf("System account %s already has a UserID assigned", systemAccountNumber))
						}
					}
				}
			}
		}

		if _, err := EnsureUserAccount(tx, nu.ID); err != nil {
			return fmt.Errorf("ensure user-account failed: %w", err)
		}
		return nil
	}); err != nil {
		// 👇 ডেভ মোডে সোজা error দেখাতে চান? তাহলে msg := err.Error() রেসপন্সে দিন।
		logger.Error("Login DB transaction failed", err)
		return c.Status(fiber.StatusInternalServerError).JSON(types.ApiResponse{
			Message: "Login succeeded but local sync failed",
			Status:  fiber.StatusInternalServerError,
			Data:    loginResp,
		})
	}

	// 4) Set cookies
	if loginResp.Access != "" {
		h.setSecureCookie(c, "access", loginResp.Access, 8*60*60)
	}
	if loginResp.Refresh != "" {
		h.setSecureCookie(c, "refresh", loginResp.Refresh, 7*24*60*60)
	}

	// 5) Structured log
	respJSON := ""
	if b, err := json.Marshal(loginResp); err == nil {
		respJSON = string(b)
	}
	h.loggerInstance.Log(types.LogEntry{
		Method:          c.Method(),
		URL:             c.OriginalURL(),
		RequestBody:     string(c.Body()),
		ResponseBody:    respJSON,
		RequestHeaders:  string(c.Request().Header.Header()),
		ResponseHeaders: string(c.Response().Header.Header()),
		StatusCode:      fiber.StatusOK,
		CreatedAt:       time.Now(),
	})

	logger.Success("User logged in successfully. uuid: " + uid + " at " + nowStr)
	return c.Status(fiber.StatusOK).JSON(loginResp)
}

// ---- Full Land ------------------------------------------------------------
func (h *AuthController) Land(c *fiber.Ctx) error {
	// 1) Parse & validate
	var req types.LandRequest
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

	// 2) Verify JWT and extract claims
	claims, err := sso.VerifyJWT(req.Access)
	log.Println("Verifying JWT token...", claims)
	if err != nil {
		log.Printf("JWT verification failed: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(types.ApiResponse{
			Message: "Invalid or expired token",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		})
	}
	fmt.Println("Verified JWT claims:", claims)

	// 3) Extract user data from claims
	uid, ok := claims["uuid"].(string)
	if !ok || strings.TrimSpace(uid) == "" {
		logger.Error("UUID not found in JWT claims", nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: "Invalid token: UUID missing",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		})
	}

	nowStr := time.Now().Format("2006-01-02 03:04:05 PM")

	// 4) Upsert user + EnsureUserAccount in one transaction (similar to login logic)
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		var u user.User

		// (A) Try by UUID (fast path: update)
		if err := tx.Where("uuid = ?", uid).First(&u).Error; err == nil {
			// User exists, update fields from JWT claims
			if username, ok := claims["username"].(string); ok {
				u.Username = username
			}
			if phone, ok := claims["phone"].(string); ok {
				u.Phone = phone
			}
			if phoneVerified, ok := claims["phone_verified"].(bool); ok {
				u.PhoneVerified = phoneVerified
			}
			if emailVerified, ok := claims["email_verified"].(bool); ok {
				u.EmailVerified = emailVerified
			}
			if avatar, ok := claims["avatar"].(string); ok {
				u.Avatar = avatar
			}
			if nonce, ok := claims["nonce"].(float64); ok {
				u.Nonce = int(nonce)
			}
			if legalName, ok := claims["legal_name"].(string); ok && legalName != "" {
				u.LegalName = legalName
			}
			if email := claims["email"]; email != nil {
				if emailStr, ok := email.(string); ok && emailStr != "" {
					u.Email = &emailStr
				}
			}
			if permissions, ok := claims["permissions"].([]interface{}); ok {
				var permStrings []string
				for _, p := range permissions {
					if pStr, ok := p.(string); ok {
						permStrings = append(permStrings, pStr)
					}
				}
				u.Permissions = user.StringSlice(permStrings)
			}

			// Handle branch_code if provided
			if branchCode, ok := claims["branch_code"].(string); ok && branchCode != "" {
				var postOfficeBranch user.PostOfficeBranch
				if err := tx.Where("branch_code = ?", branchCode).First(&postOfficeBranch).Error; err == nil {
					u.PostOfficeBranchID = &postOfficeBranch.ID
					logger.Info(fmt.Sprintf("Found PostOfficeBranch with code %s, assigned to user %s", branchCode, uid))
				} else if errors.Is(err, gorm.ErrRecordNotFound) {
					logger.Warning(fmt.Sprintf("PostOfficeBranch with code %s not found for user %s", branchCode, uid))
				} else {
					logger.Error(fmt.Sprintf("Error finding PostOfficeBranch with code %s", branchCode), err)
				}

				// Check if user has post-master or postmaster permissions
				hasPostMasterPermission := false
				if permissions, ok := claims["permissions"].([]interface{}); ok {
					for _, permission := range permissions {
						if pStr, ok := permission.(string); ok {
							if strings.Contains(strings.ToLower(pStr), "post-master") || strings.Contains(strings.ToLower(pStr), "postmaster") {
								hasPostMasterPermission = true
								break
							}
						}
					}
				}

				if hasPostMasterPermission {
					// Create system account with S + BranchCode
					systemAccountNumber := "S" + branchCode
					logger.Info(fmt.Sprintf("User %s has post-master permission, creating/finding system account %s", uid, systemAccountNumber))

					var systemAccount account.Account
					// Try to find existing system account
					if err := tx.Where("account_number = ?", systemAccountNumber).First(&systemAccount).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							// Create new system account
							systemAccount = account.Account{
								AccountNumber:   systemAccountNumber,
								CurrentBalance:  0.00,
								AccountType:     "system",
								IsActive:        true,
								IsLocked:        false,
								CreatedAt:       ptrTime(time.Now()),
								UpdatedAt:       ptrTime(time.Now()),
								MaxLimit:        0.00,
								BalanceType:     "system",
								Currency:        "BDT",
								IsSystemAccount: true,
							}
							if err := tx.Create(&systemAccount).Error; err != nil {
								logger.Error(fmt.Sprintf("Failed to create system account %s", systemAccountNumber), err)
							} else {
								logger.Success(fmt.Sprintf("Created system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
							}
						} else {
							logger.Error(fmt.Sprintf("Error finding system account %s", systemAccountNumber), err)
						}
					} else {
						logger.Info(fmt.Sprintf("Found existing system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
					}

					// Find or create AccountOwner for the system account
					if systemAccount.ID > 0 {
						var systemAccountOwner account.AccountOwner
						if err := tx.Where("account_id = ?", systemAccount.ID).First(&systemAccountOwner).Error; err != nil {
							if errors.Is(err, gorm.ErrRecordNotFound) {
								// Create new AccountOwner
								defaultOrgID := uint(1) // Use default org ID
								systemAccountOwner = account.AccountOwner{
									UserID:             &u.ID,
									AccountID:          &systemAccount.ID,
									OrgID:              &defaultOrgID,
									PostOfficeBranchID: u.PostOfficeBranchID,
								}
								if err := tx.Create(&systemAccountOwner).Error; err != nil {
									logger.Error(fmt.Sprintf("Failed to create AccountOwner for system account %s", systemAccountNumber), err)
								} else {
									logger.Success(fmt.Sprintf("Created AccountOwner for system account %s, assigned to user %s", systemAccountNumber, uid))
								}
							} else {
								logger.Error(fmt.Sprintf("Error finding AccountOwner for system account %s", systemAccountNumber), err)
							}
						} else {
							// AccountOwner exists, check if UserID is empty and assign if needed
							if systemAccountOwner.UserID == nil {
								systemAccountOwner.UserID = &u.ID
								systemAccountOwner.PostOfficeBranchID = u.PostOfficeBranchID
								if err := tx.Save(&systemAccountOwner).Error; err != nil {
									logger.Error(fmt.Sprintf("Failed to assign user to AccountOwner for system account %s", systemAccountNumber), err)
								} else {
									logger.Success(fmt.Sprintf("Assigned user %s to existing AccountOwner for system account %s", uid, systemAccountNumber))
								}
							} else {
								logger.Info(fmt.Sprintf("System account %s already has a UserID assigned", systemAccountNumber))
							}
						}
					}
				}
			}

			if err := tx.Save(&u).Error; err != nil {
				return fmt.Errorf("update user by uuid failed: %w", err)
			}
			if _, err := EnsureUserAccount(tx, u.ID); err != nil {
				return fmt.Errorf("ensure user-account failed: %w", err)
			}
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("query user by uuid failed: %w", err)
		}

		// (B) Not found by UUID → try by Phone (merge into existing record)
		if phone, ok := claims["phone"].(string); ok && strings.TrimSpace(phone) != "" {
			if err := tx.Where("phone = ?", phone).First(&u).Error; err == nil {
				// Merge: attach SSO uuid + update fields
				u.Uuid = uid
				if username, ok := claims["username"].(string); ok {
					u.Username = username
				}
				if phoneVerified, ok := claims["phone_verified"].(bool); ok {
					u.PhoneVerified = phoneVerified
				}
				if emailVerified, ok := claims["email_verified"].(bool); ok {
					u.EmailVerified = emailVerified
				}
				if avatar, ok := claims["avatar"].(string); ok {
					u.Avatar = avatar
				}
				if nonce, ok := claims["nonce"].(float64); ok {
					u.Nonce = int(nonce)
				}
				if legalName, ok := claims["legal_name"].(string); ok && legalName != "" {
					u.LegalName = legalName
				}
				if email := claims["email"]; email != nil {
					if emailStr, ok := email.(string); ok && emailStr != "" {
						u.Email = &emailStr
					}
				}
				if permissions, ok := claims["permissions"].([]interface{}); ok {
					var permStrings []string
					for _, p := range permissions {
						if pStr, ok := p.(string); ok {
							permStrings = append(permStrings, pStr)
						}
					}
					u.Permissions = user.StringSlice(permStrings)
				}

				// Handle branch_code if provided
				if branchCode, ok := claims["branch_code"].(string); ok && branchCode != "" {
					var postOfficeBranch user.PostOfficeBranch
					if err := tx.Where("branch_code = ?", branchCode).First(&postOfficeBranch).Error; err == nil {
						u.PostOfficeBranchID = &postOfficeBranch.ID
						logger.Info(fmt.Sprintf("Found PostOfficeBranch with code %s, assigned to user %s", branchCode, uid))
					} else if errors.Is(err, gorm.ErrRecordNotFound) {
						logger.Warning(fmt.Sprintf("PostOfficeBranch with code %s not found for user %s", branchCode, uid))
					} else {
						logger.Error(fmt.Sprintf("Error finding PostOfficeBranch with code %s", branchCode), err)
					}

					// Check if user has post-master or postmaster permissions
					hasPostMasterPermission := false
					if permissions, ok := claims["permissions"].([]interface{}); ok {
						for _, permission := range permissions {
							if pStr, ok := permission.(string); ok {
								if strings.Contains(strings.ToLower(pStr), "post-master") || strings.Contains(strings.ToLower(pStr), "postmaster") {
									hasPostMasterPermission = true
									break
								}
							}
						}
					}

					if hasPostMasterPermission {
						// Create system account with S + BranchCode
						systemAccountNumber := "S" + branchCode
						logger.Info(fmt.Sprintf("User %s has post-master permission, creating/finding system account %s", uid, systemAccountNumber))

						var systemAccount account.Account
						// Try to find existing system account
						if err := tx.Where("account_number = ?", systemAccountNumber).First(&systemAccount).Error; err != nil {
							if errors.Is(err, gorm.ErrRecordNotFound) {
								// Create new system account
								systemAccount = account.Account{
									AccountNumber:   systemAccountNumber,
									CurrentBalance:  0.00,
									AccountType:     "system",
									IsActive:        true,
									IsLocked:        false,
									CreatedAt:       ptrTime(time.Now()),
									UpdatedAt:       ptrTime(time.Now()),
									MaxLimit:        0.00,
									BalanceType:     "system",
									Currency:        "BDT",
									IsSystemAccount: true,
								}
								if err := tx.Create(&systemAccount).Error; err != nil {
									logger.Error(fmt.Sprintf("Failed to create system account %s", systemAccountNumber), err)
								} else {
									logger.Success(fmt.Sprintf("Created system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
								}
							} else {
								logger.Error(fmt.Sprintf("Error finding system account %s", systemAccountNumber), err)
							}
						} else {
							logger.Info(fmt.Sprintf("Found existing system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
						}

						// Find or create AccountOwner for the system account
						if systemAccount.ID > 0 {
							var systemAccountOwner account.AccountOwner
							if err := tx.Where("account_id = ?", systemAccount.ID).First(&systemAccountOwner).Error; err != nil {
								if errors.Is(err, gorm.ErrRecordNotFound) {
									// Create new AccountOwner
									defaultOrgID := uint(1) // Use default org ID
									systemAccountOwner = account.AccountOwner{
										UserID:             &u.ID,
										AccountID:          &systemAccount.ID,
										OrgID:              &defaultOrgID,
										PostOfficeBranchID: u.PostOfficeBranchID,
									}
									if err := tx.Create(&systemAccountOwner).Error; err != nil {
										logger.Error(fmt.Sprintf("Failed to create AccountOwner for system account %s", systemAccountNumber), err)
									} else {
										logger.Success(fmt.Sprintf("Created AccountOwner for system account %s, assigned to user %s", systemAccountNumber, uid))
									}
								} else {
									logger.Error(fmt.Sprintf("Error finding AccountOwner for system account %s", systemAccountNumber), err)
								}
							} else {
								// AccountOwner exists, check if UserID is empty and assign if needed
								if systemAccountOwner.UserID == nil {
									systemAccountOwner.UserID = &u.ID
									systemAccountOwner.PostOfficeBranchID = u.PostOfficeBranchID
									if err := tx.Save(&systemAccountOwner).Error; err != nil {
										logger.Error(fmt.Sprintf("Failed to assign user to AccountOwner for system account %s", systemAccountNumber), err)
									} else {
										logger.Success(fmt.Sprintf("Assigned user %s to existing AccountOwner for system account %s", uid, systemAccountNumber))
									}
								} else {
									logger.Info(fmt.Sprintf("System account %s already has a UserID assigned", systemAccountNumber))
								}
							}
						}
					}
				}

				if err := tx.Save(&u).Error; err != nil {
					return fmt.Errorf("merge user by phone failed: %w", err)
				}
				if _, err := EnsureUserAccount(tx, u.ID); err != nil {
					return fmt.Errorf("ensure user-account failed: %w", err)
				}
				return nil
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("query user by phone failed: %w", err)
			}
		}

		// (C) Create new user (no uuid/phone match)
		nu := user.User{
			Uuid: uid,
		}

		// Populate fields from JWT claims
		if username, ok := claims["username"].(string); ok {
			nu.Username = username
		}
		if phone, ok := claims["phone"].(string); ok {
			nu.Phone = phone
		}
		if phoneVerified, ok := claims["phone_verified"].(bool); ok {
			nu.PhoneVerified = phoneVerified
		}
		if emailVerified, ok := claims["email_verified"].(bool); ok {
			nu.EmailVerified = emailVerified
		}
		if avatar, ok := claims["avatar"].(string); ok {
			nu.Avatar = avatar
		}
		if nonce, ok := claims["nonce"].(float64); ok {
			nu.Nonce = int(nonce)
		}
		if legalName, ok := claims["legal_name"].(string); ok && legalName != "" {
			nu.LegalName = legalName
		}
		if email := claims["email"]; email != nil {
			if emailStr, ok := email.(string); ok && emailStr != "" {
				nu.Email = &emailStr
			}
		}
		if permissions, ok := claims["permissions"].([]interface{}); ok {
			var permStrings []string
			for _, p := range permissions {
				if pStr, ok := p.(string); ok {
					permStrings = append(permStrings, pStr)
				}
			}
			nu.Permissions = user.StringSlice(permStrings)
		}

		// Handle branch_code if provided
		if branchCode, ok := claims["branch_code"].(string); ok && branchCode != "" {
			var postOfficeBranch user.PostOfficeBranch
			if err := tx.Where("branch_code = ?", branchCode).First(&postOfficeBranch).Error; err == nil {
				nu.PostOfficeBranchID = &postOfficeBranch.ID
				logger.Info(fmt.Sprintf("Found PostOfficeBranch with code %s, assigned to new user %s", branchCode, uid))
			} else if errors.Is(err, gorm.ErrRecordNotFound) {
				logger.Warning(fmt.Sprintf("PostOfficeBranch with code %s not found for new user %s", branchCode, uid))
			} else {
				logger.Error(fmt.Sprintf("Error finding PostOfficeBranch with code %s for new user", branchCode), err)
			}
		}

		// Create with "ON CONFLICT DO NOTHING" to swallow rare races; then fetch by uuid
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&nu).Error; err != nil {
			return fmt.Errorf("create user failed: %w", err)
		}
		// Fetch back (covers DoNothing case)
		if err := tx.Where("uuid = ?", uid).First(&nu).Error; err != nil {
			return fmt.Errorf("fetch created user failed: %w", err)
		}

		// Handle post-master system account creation after user is created and has ID
		if branchCode, ok := claims["branch_code"].(string); ok && branchCode != "" {
			// Check if user has post-master or postmaster permissions
			hasPostMasterPermission := false
			if permissions, ok := claims["permissions"].([]interface{}); ok {
				for _, permission := range permissions {
					if pStr, ok := permission.(string); ok {
						if strings.Contains(strings.ToLower(pStr), "post-master") || strings.Contains(strings.ToLower(pStr), "postmaster") {
							hasPostMasterPermission = true
							break
						}
					}
				}
			}

			if hasPostMasterPermission {
				// Create system account with S + BranchCode
				systemAccountNumber := "S" + branchCode
				logger.Info(fmt.Sprintf("New user %s has post-master permission, creating/finding system account %s", uid, systemAccountNumber))

				var systemAccount account.Account
				// Try to find existing system account
				if err := tx.Where("account_number = ?", systemAccountNumber).First(&systemAccount).Error; err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						// Create new system account
						systemAccount = account.Account{
							AccountNumber:   systemAccountNumber,
							CurrentBalance:  0.00,
							AccountType:     "system",
							IsActive:        true,
							IsLocked:        false,
							CreatedAt:       ptrTime(time.Now()),
							UpdatedAt:       ptrTime(time.Now()),
							MaxLimit:        0.00,
							BalanceType:     "system",
							Currency:        "BDT",
							IsSystemAccount: true,
						}
						if err := tx.Create(&systemAccount).Error; err != nil {
							logger.Error(fmt.Sprintf("Failed to create system account %s", systemAccountNumber), err)
						} else {
							logger.Success(fmt.Sprintf("Created system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
						}
					} else {
						logger.Error(fmt.Sprintf("Error finding system account %s", systemAccountNumber), err)
					}
				} else {
					logger.Info(fmt.Sprintf("Found existing system account %s with ID: %d", systemAccountNumber, systemAccount.ID))
				}

				// Find or create AccountOwner for the system account
				if systemAccount.ID > 0 {
					var systemAccountOwner account.AccountOwner
					if err := tx.Where("account_id = ?", systemAccount.ID).First(&systemAccountOwner).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							// Create new AccountOwner
							defaultOrgID := uint(1) // Use default org ID
							systemAccountOwner = account.AccountOwner{
								UserID:             &nu.ID,
								AccountID:          &systemAccount.ID,
								OrgID:              &defaultOrgID,
								PostOfficeBranchID: nu.PostOfficeBranchID,
							}
							if err := tx.Create(&systemAccountOwner).Error; err != nil {
								logger.Error(fmt.Sprintf("Failed to create AccountOwner for system account %s", systemAccountNumber), err)
							} else {
								logger.Success(fmt.Sprintf("Created AccountOwner for system account %s, assigned to new user %s", systemAccountNumber, uid))
							}
						} else {
							logger.Error(fmt.Sprintf("Error finding AccountOwner for system account %s", systemAccountNumber), err)
						}
					} else {
						// AccountOwner exists, check if UserID is empty and assign if needed
						if systemAccountOwner.UserID == nil {
							systemAccountOwner.UserID = &nu.ID
							systemAccountOwner.PostOfficeBranchID = nu.PostOfficeBranchID
							if err := tx.Save(&systemAccountOwner).Error; err != nil {
								logger.Error(fmt.Sprintf("Failed to assign new user to AccountOwner for system account %s", systemAccountNumber), err)
							} else {
								logger.Success(fmt.Sprintf("Assigned new user %s to existing AccountOwner for system account %s", uid, systemAccountNumber))
							}
						} else {
							logger.Info(fmt.Sprintf("System account %s already has a UserID assigned", systemAccountNumber))
						}
					}
				}
			}
		}

		if _, err := EnsureUserAccount(tx, nu.ID); err != nil {
			return fmt.Errorf("ensure user-account failed: %w", err)
		}
		return nil
	}); err != nil {
		logger.Error("Land DB transaction failed", err)
		return c.Status(fiber.StatusInternalServerError).JSON(types.ApiResponse{
			Message: "Token verified but local sync failed",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		})
	}

	// 5) Structured log
	h.loggerInstance.Log(types.LogEntry{
		Method:          c.Method(),
		URL:             c.OriginalURL(),
		RequestBody:     string(c.Body()),
		ResponseBody:    `{"message": "Land successful", "status": 200}`,
		RequestHeaders:  string(c.Request().Header.Header()),
		ResponseHeaders: string(c.Response().Header.Header()),
		StatusCode:      fiber.StatusOK,
		CreatedAt:       time.Now(),
	})

	logger.Success("User landed successfully. uuid: " + uid + " at " + nowStr)
	return c.Status(fiber.StatusOK).JSON(types.ApiResponse{
		Message: "Land successful",
		Status:  fiber.StatusOK,
		Data: map[string]interface{}{
			"uuid": uid,
		},
	})
}

func (h *AuthController) GetServiceToken(c *fiber.Ctx) error {
	var req types.GetServiceTokenRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing request body", err)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: "Invalid request payload",
			Status:  fiber.StatusBadRequest,
		})
	}

	if validationErr := req.Validate(); validationErr != "" {
		logger.Error(validationErr, nil)
		return c.Status(fiber.StatusBadRequest).JSON(types.ApiResponse{
			Message: validationErr,
			Status:  fiber.StatusBadRequest,
		})
	}

	// Make call to external API through the service
	redirectToken, err := h.httpService.RequestRedirectToken(httpServices.ServiceUserRequest{
		InternalIdentifier: req.InternalIdentifier,
		RedirectURL:        req.RedirectURL,
		UserType:           req.UserType,
	})
	if err != nil {
		logger.Error("Failed to retrieve redirect token", err)
		return c.Status(fiber.StatusBadGateway).JSON(types.ApiResponse{
			Message: "Failed to communicate with external service",
			Status:  fiber.StatusBadGateway,
		})
	}

	currentTime := time.Now().Format("2006-01-02 03:04:05 PM")

	// Generate your actual response
	response := types.ApiResponse{
		Message: "Got redirect token Successfully!!!",
		Status:  fiber.StatusOK,
		Data: map[string]interface{}{
			"redirect_token": redirectToken,
		},
	}

	logger.Success("User token got successfully. Redirect token: " + redirectToken + " at " + currentTime)
	return c.Status(fiber.StatusOK).JSON(response)
}

func (h *AuthController) LogOut(c *fiber.Ctx) error {
	// Get the token from the Authorization header
	tokenStr := c.Get("Authorization")
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

	// Clear the access and refresh cookies
	h.setSecureCookie(c, "access", "", -1)  // Expire immediately
	h.setSecureCookie(c, "refresh", "", -1) // Expire immediately

	response := types.ApiResponse{
		Message: "Logout successful",
		Status:  fiber.StatusOK,
		Data:    nil,
	}
	logger.Success("Logout successful")
	return c.Status(fiber.StatusOK).JSON(response)
}
