package database

import (
	"dms-accounting/logger"
	"dms-accounting/models/organization"
	"dms-accounting/models/user"
	"time"

	"gorm.io/gorm"
)

// SeedData seeds the database with initial data
func SeedData(db *gorm.DB) error {
	logger.Success("🌱 Starting database seeding...")

	// Seed default organization
	if err := seedDefaultOrganization(db); err != nil {
		return err
	}

	// Seed address data from JSON files
	if err := SeedAddressDataFromJSON(db); err != nil {
		return err
	}

	// Seed system accounts for post office branches
	if err := SeedSystemAccountsForPostOfficeBranches(db); err != nil {
		return err
	}

	logger.Success("✅ Database seeding completed successfully")
	return nil
}

// seedDefaultOrganization creates the default Bangladesh Post Office organization
func seedDefaultOrganization(db *gorm.DB) error {
	// Check if default organization already exists
	var existingOrg organization.Organization
	err := db.Where("code = ?", "BPO").First(&existingOrg).Error
	if err == nil {
		logger.Debug("Default organization already exists, skipping...")
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		logger.Error("Error checking for existing organization", err)
		return err
	}

	// Create default organization
	now := time.Now()
	defaultOrg := organization.Organization{
		Name:       "Bangladesh Post Office",
		Code:       "BPO",
		Type:       "government",
		Status:     "active",
		IsActive:   true,
		ApprovedAt: &now,
		CreatedAt:  now,
		UpdatedAt:  now,
		// CreatedByID and ApprovedByID will be nil for system-created org
	}

	if err := db.Create(&defaultOrg).Error; err != nil {
		logger.Error("Failed to create default organization", err)
		return err
	}

	// Create a default address for the organization
	defaultAddress := user.Address{
		Name:          stringPtr("Bangladesh Post Office Head Office"),
		StreetAddress: stringPtr("GPO Box 000, Dhaka-1000, Bangladesh"),
		Phone:         stringPtr("+880-2-9551234"),
		// We'll leave the other address fields as nil since they reference other tables
		// that may not be created yet
	}

	if err := db.Create(&defaultAddress).Error; err != nil {
		logger.Error("Failed to create default address", err)
		return err
	}

	// Create organization info for the default organization
	orgInfo := organization.OrganizationInfo{
		OrganizationID: defaultOrg.ID,
		LegalName:      "Bangladesh Post Office",
		TradeName:      stringPtr("Bangladesh Post"),
		RegistrationNo: stringPtr("BPO-GOV-001"),
		Email:          stringPtr("info@bangladeshpost.gov.bd"),
		Phone:          stringPtr("+880-2-9551234"),
		Website:        stringPtr("https://www.bangladeshpost.gov.bd"),
		AddressID:      defaultAddress.ID, // Use the created address ID
		Industry:       stringPtr("Postal Services"),
		EmployeeCount:  intPtr(50000),
		EstablishedAt:  timePtr(time.Date(1971, 12, 16, 0, 0, 0, 0, time.UTC)),
		Description:    stringPtr("The national postal service of Bangladesh, providing postal and financial services across the country."),
	}

	if err := db.Create(&orgInfo).Error; err != nil {
		logger.Error("Failed to create default organization info", err)
		return err
	}

	logger.Success("✅ Default organization 'Bangladesh Post Office' created successfully")
	return nil
}

// GetDefaultOrganizationID returns the ID of the default Bangladesh Post Office organization
func GetDefaultOrganizationID(db *gorm.DB) (uint, error) {
	var org organization.Organization
	err := db.Where("code = ?", "BPO").First(&org).Error
	if err != nil {
		return 0, err
	}
	return org.ID, nil
}

// Helper functions for creating pointers
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func timePtr(t time.Time) *time.Time {
	return &t
}
