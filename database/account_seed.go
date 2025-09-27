package database

import (
	"dms-accounting/logger"
	"dms-accounting/models/account"
	"dms-accounting/models/user"
	"fmt"

	"gorm.io/gorm"
)

// SeedSystemAccountsForPostOfficeBranches creates system accounts for the first 10 post office branches (for testing)
// Each account will have:
// - AccountNumber: S + 6-digit branch code
// - AccountName: Post Office Branch name
// - IsActive: false, IsLocked: true
// - AccountType: "DMS", Currency: "BDT"
func SeedSystemAccountsForPostOfficeBranches(db *gorm.DB) error {
	logger.Info("🏦 Starting to seed system accounts for first 10 post office branches...")

	// Get the default organization ID
	defaultOrgID, err := GetDefaultOrganizationID(db)
	if err != nil {
		logger.Error("Failed to get default organization ID", err)
		return fmt.Errorf("failed to get default organization ID: %w", err)
	}

	// Check if accounts already exist to avoid duplicate seeding
	var existingAccountCount int64
	db.Model(&account.Account{}).Where("is_system_account = ? AND account_type = ?", true, "DMS").Count(&existingAccountCount)

	// Get first 10 post office branches for initial seeding
	var postOfficeBranches []user.PostOfficeBranch
	if err := db.Find(&postOfficeBranches).Error; err != nil {
		logger.Error("Failed to fetch post office branches", err)
		return fmt.Errorf("failed to fetch post office branches: %w", err)
	}

	if len(postOfficeBranches) == 0 {
		logger.Warning("⚠️  No post office branches found. Make sure to seed address data first.")
		return nil
	}

	// Count how many of these first 10 branches already have system accounts
	var branchesWithAccounts int64
	if len(postOfficeBranches) > 0 {
		// Get IDs of first 10 branches
		branchIDs := make([]uint, len(postOfficeBranches))
		for i, branch := range postOfficeBranches {
			branchIDs[i] = branch.ID
		}

		db.Model(&account.AccountOwner{}).
			Where("org_id = ? AND post_office_branch_id IN ?", defaultOrgID, branchIDs).
			Count(&branchesWithAccounts)
	}

	if branchesWithAccounts >= int64(len(postOfficeBranches)) {
		logger.Debug("System accounts already exist for first 10 post office branches, skipping...")
		return nil
	}

	logger.Info(fmt.Sprintf("📊 Processing first 10 post office branches: found %d branches, %d already have system accounts. Creating accounts for remaining branches...",
		len(postOfficeBranches), branchesWithAccounts))

	successCount := 0
	errorCount := 0
	skippedCount := 0

	// Create system accounts for each post office branch
	for _, branch := range postOfficeBranches {
		// Check if this branch already has a system account
		var existingOwner account.AccountOwner
		err := db.Where("org_id = ? AND post_office_branch_id = ?", defaultOrgID, branch.ID).First(&existingOwner).Error
		if err == nil {
			skippedCount++
			continue // Account already exists for this branch
		}
		if err != gorm.ErrRecordNotFound {
			logger.Error(fmt.Sprintf("Error checking existing account for branch ID %d", branch.ID), err)
			errorCount++
			continue
		}

		// Generate account number using branch code
		accountNumber := generateAccountNumber(branch)

		// Get branch name for account name
		branchName := getBranchName(branch)

		// Create the system account
		systemAccount := account.Account{
			AccountNumber:   accountNumber,
			AccountName:     &branchName,
			CurrentBalance:  0.00,
			AccountType:     "DMS",
			IsActive:        false,
			IsLocked:        true,
			Currency:        "BDT",
			IsSystemAccount: true,
			MaxLimit:        0.00,
			BalanceType:     "system",
		}

		// Create account in database
		if err := db.Create(&systemAccount).Error; err != nil {
			logger.Error(fmt.Sprintf("Failed to create system account for branch ID %d (%s) with account number %s: %v",
				branch.ID, getBranchName(branch), accountNumber, err), nil)
			errorCount++
			continue
		}

		// Create account owner record (no UserID, only OrgID and PostOfficeBranchID)
		accountOwner := account.AccountOwner{
			UserID:             nil, // No user owner for system accounts
			AccountID:          &systemAccount.ID,
			OrgID:              &defaultOrgID,
			PostOfficeBranchID: &branch.ID,
		}

		if err := db.Create(&accountOwner).Error; err != nil {
			logger.Error(fmt.Sprintf("Failed to create account owner for branch ID %d (%s): %v",
				branch.ID, getBranchName(branch), err), nil)

			// Rollback: delete the account we just created
			db.Delete(&systemAccount)
			errorCount++
			continue
		}

		successCount++

		// Log each account creation for the first 10 branches
		logger.Info(fmt.Sprintf("✅ Created account %s (%s) for branch ID %d",
			accountNumber, branchName, branch.ID))
	}

	logger.Success(fmt.Sprintf("✅ System account seeding completed for first 10 post office branches: %d created, %d skipped, %d errors",
		successCount, skippedCount, errorCount))

	if errorCount > 0 {
		logger.Warning(fmt.Sprintf("⚠️  %d accounts failed to create. Check logs for details.", errorCount))
	}

	return nil
}

// ForceReseedSystemAccounts deletes existing system accounts and recreates them
func ForceReseedSystemAccounts(db *gorm.DB) error {
	logger.Warning("⚠️  Force re-seeding system accounts (this will delete existing system accounts)...")

	// Get the default organization ID
	defaultOrgID, err := GetDefaultOrganizationID(db)
	if err != nil {
		logger.Error("Failed to get default organization ID", err)
		return fmt.Errorf("failed to get default organization ID: %w", err)
	}

	// Delete existing system account owners for the default organization
	result := db.Where("org_id = ? AND user_id IS NULL", defaultOrgID).Delete(&account.AccountOwner{})
	if result.Error != nil {
		logger.Error("Failed to delete existing system account owners", result.Error)
		return result.Error
	}
	logger.Info(fmt.Sprintf("✅ Deleted %d existing system account owners", result.RowsAffected))

	// Delete existing system accounts
	result = db.Where("is_system_account = ? AND account_type = ?", true, "DMS").Delete(&account.Account{})
	if result.Error != nil {
		logger.Error("Failed to delete existing system accounts", result.Error)
		return result.Error
	}
	logger.Info(fmt.Sprintf("✅ Deleted %d existing system accounts", result.RowsAffected))

	// Now seed fresh system accounts
	return SeedSystemAccountsForPostOfficeBranches(db)
}

// generateAccountNumber creates a unique account number based on branch code
// Format: S + 6-digit branch code (total 7 digits)
// Examples:
//   - Branch code "100042" → "S100042"
//   - Branch code "0000" (4 digits) → "S000000" (adds "00" at end)
//   - Branch ID 3228 (no branch code) → "S322800" (ID + "00")
//   - Branch code "12345" → "S123500" (adds "0" at end to make 6 digits)
func generateAccountNumber(branch user.PostOfficeBranch) string {
	// Get branch code, default to ID if branch code is nil
	var branchCode string
	if branch.BranchCode != nil && *branch.BranchCode != "" {
		branchCode = *branch.BranchCode

		// Handle different branch code lengths
		switch len(branchCode) {
		case 4:
			// 4-digit codes: add "00" at the end
			branchCode = branchCode + "00"
		case 5:
			// 5-digit codes: add "0" at the end
			branchCode = branchCode + "0"
		case 6:
			// 6-digit codes: use as is
			// branchCode remains unchanged
		default:
			if len(branchCode) < 4 {
				// Less than 4 digits: pad with leading zeros then add "00"
				branchCode = fmt.Sprintf("%04s00", branchCode)
			} else if len(branchCode) > 6 {
				// More than 6 digits: truncate to 6
				branchCode = branchCode[:6]
			}
		}
	} else {
		// Use branch ID + "00" as fallback for branches without branch code
		branchCode = fmt.Sprintf("%d00", branch.ID)
		// Ensure it's exactly 6 digits
		if len(branchCode) > 6 {
			branchCode = branchCode[:6]
		} else if len(branchCode) < 6 {
			branchCode = fmt.Sprintf("%06s", branchCode)
		}
	}

	return fmt.Sprintf("S%s", branchCode)
} // getBranchName safely gets the branch name for logging
func getBranchName(branch user.PostOfficeBranch) string {
	if branch.Name != nil {
		return *branch.Name
	}
	if branch.EnName != nil {
		return *branch.EnName
	}
	return "Unknown Branch"
}

// ValidateSystemAccountsIntegrity checks if system accounts are properly created
func ValidateSystemAccountsIntegrity(db *gorm.DB) error {
	logger.Info("🔍 Validating system accounts integrity...")

	// Get counts
	var totalBranches, systemAccounts, accountOwners int64

	db.Model(&user.PostOfficeBranch{}).Count(&totalBranches)
	db.Model(&account.Account{}).Where("is_system_account = ? AND account_type = ?", true, "DMS").Count(&systemAccounts)
	db.Model(&account.AccountOwner{}).Where("user_id IS NULL AND post_office_branch_id IS NOT NULL").Count(&accountOwners)

	logger.Info(fmt.Sprintf("📊 System accounts summary: %d branches, %d system accounts, %d account owners",
		totalBranches, systemAccounts, accountOwners))

	// Check for orphaned accounts (accounts without owners)
	var orphanedAccounts int64
	db.Model(&account.Account{}).
		Joins("LEFT JOIN account_owners ON account_owners.account_id = accounts.id").
		Where("accounts.is_system_account = ? AND accounts.account_type = ? AND account_owners.id IS NULL", true, "DMS").
		Count(&orphanedAccounts)

	// Check for orphaned owners (owners without accounts)
	var orphanedOwners int64
	db.Model(&account.AccountOwner{}).
		Joins("LEFT JOIN accounts ON accounts.id = account_owners.account_id").
		Where("account_owners.user_id IS NULL AND account_owners.post_office_branch_id IS NOT NULL AND accounts.id IS NULL").
		Count(&orphanedOwners)

	if orphanedAccounts > 0 || orphanedOwners > 0 {
		return fmt.Errorf("system accounts integrity issues found: orphaned accounts: %d, orphaned owners: %d",
			orphanedAccounts, orphanedOwners)
	}

	if systemAccounts != accountOwners {
		logger.Warning(fmt.Sprintf("⚠️  Mismatch: %d system accounts but %d account owners", systemAccounts, accountOwners))
	}

	logger.Success("✅ System accounts integrity validation passed")
	return nil
}

// SeedAccountsFromCommand allows manual seeding of accounts via command
// This can be called from CLI or admin endpoints for maintenance
// Currently limited to first 10 post office branches for testing
//
// Usage examples:
//   - Normal seeding (skip existing): SeedAccountsFromCommand(db, false)
//   - Force reseed (delete and recreate): SeedAccountsFromCommand(db, true)
//
// Account number format: S + 6-digit branch code
// - 6-digit codes: "S100042"
// - 4-digit codes: "S000000" (4-digit + "00")
// - No branch code: "S322800" (ID + "00")
func SeedAccountsFromCommand(db *gorm.DB, forceReseed bool) error {
	if forceReseed {
		logger.Info("🔄 Force reseeding system accounts...")
		return ForceReseedSystemAccounts(db)
	} else {
		logger.Info("🌱 Seeding system accounts (existing accounts will be skipped)...")
		return SeedSystemAccountsForPostOfficeBranches(db)
	}
}
