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

	// Seed address data
	if err := seedAddressData(db); err != nil {
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

// seedAddressData creates sample address hierarchy data
func seedAddressData(db *gorm.DB) error {
	// Check if divisions already exist
	var divisionCount int64
	db.Model(&user.Division{}).Count(&divisionCount)
	if divisionCount > 0 {
		logger.Debug("Address data already exists, skipping...")
		return nil
	}

	// Create sample divisions
	divisions := []user.Division{
		{EnName: "Dhaka", BnName: "ঢাকা", Slug: "dhaka"},
		{EnName: "Chittagong", BnName: "চট্টগ্রাম", Slug: "chittagong"},
		{EnName: "Sylhet", BnName: "সিলেট", Slug: "sylhet"},
	}

	for _, division := range divisions {
		if err := db.Create(&division).Error; err != nil {
			logger.Error("Failed to create division", err)
			return err
		}
	}

	// Create sample districts for Dhaka division
	var dhakaDivision user.Division
	if err := db.Where("slug = ?", "dhaka").First(&dhakaDivision).Error; err != nil {
		logger.Error("Failed to find Dhaka division", err)
		return err
	}

	districts := []user.District{
		{DivisionID: dhakaDivision.ID, EnName: "Dhaka", BnName: "ঢাকা", Slug: "dhaka"},
		{DivisionID: dhakaDivision.ID, EnName: "Gazipur", BnName: "গাজীপুর", Slug: "gazipur"},
		{DivisionID: dhakaDivision.ID, EnName: "Narayanganj", BnName: "নারায়ণগঞ্জ", Slug: "narayanganj"},
	}

	for _, district := range districts {
		if err := db.Create(&district).Error; err != nil {
			logger.Error("Failed to create district", err)
			return err
		}
	}

	// Create sample police stations for Dhaka district
	var dhakaDistrict user.District
	if err := db.Where("slug = ? AND division_id = ?", "dhaka", dhakaDivision.ID).First(&dhakaDistrict).Error; err != nil {
		logger.Error("Failed to find Dhaka district", err)
		return err
	}

	policeStations := []user.PoliceStation{
		{DistrictID: dhakaDistrict.ID, EnName: "Dhanmondi", BnName: "ধানমন্ডি", Slug: "dhanmondi"},
		{DistrictID: dhakaDistrict.ID, EnName: "Wari", BnName: "ওয়ারী", Slug: "wari"},
		{DistrictID: dhakaDistrict.ID, EnName: "Gulshan", BnName: "গুলশান", Slug: "gulshan"},
	}

	for _, ps := range policeStations {
		if err := db.Create(&ps).Error; err != nil {
			logger.Error("Failed to create police station", err)
			return err
		}
	}

	// Create sample post offices for Dhanmondi police station
	var dhanmondiPS user.PoliceStation
	if err := db.Where("slug = ? AND district_id = ?", "dhanmondi", dhakaDistrict.ID).First(&dhanmondiPS).Error; err != nil {
		logger.Error("Failed to find Dhanmondi police station", err)
		return err
	}

	postOffices := []user.PostOffice{
		{PoliceStationID: dhanmondiPS.ID, EnName: "Dhanmondi Post Office", BnName: "ধানমন্ডি পোস্ট অফিস", Slug: "dhanmondi-post-office", PostCode: "1205"},
		{PoliceStationID: dhanmondiPS.ID, EnName: "New Market Post Office", BnName: "নিউ মার্কেট পোস্ট অফিস", Slug: "new-market-post-office", PostCode: "1205"},
	}

	for _, po := range postOffices {
		if err := db.Create(&po).Error; err != nil {
			logger.Error("Failed to create post office", err)
			return err
		}
	}

	// Create sample post office branches
	var dhanmondiPO user.PostOffice
	if err := db.Where("slug = ? AND police_station_id = ?", "dhanmondi-post-office", dhanmondiPS.ID).First(&dhanmondiPO).Error; err != nil {
		logger.Error("Failed to find Dhanmondi post office", err)
		return err
	}

	branches := []user.PostOfficeBranch{
		{
			PostOfficeID: &dhanmondiPO.ID,
			Name:         stringPtr("Dhanmondi Main Branch"),
			BnName:       stringPtr("ধানমন্ডি প্রধান শাখা"),
			BranchCode:   stringPtr("100000"),
			Circle:       stringPtr("Dhaka"),
			District:     stringPtr("Dhaka"),
			Status:       stringPtr("active"),
			IsOpen:       stringPtr("yes"),
			Shift:        stringPtr("full"),
		},
		{
			PostOfficeID: &dhanmondiPO.ID,
			Name:         stringPtr("Dhanmondi Sub Branch"),
			BnName:       stringPtr("ধানমন্ডি উপ-শাখা"),
			BranchCode:   stringPtr("100001"),
			Circle:       stringPtr("Dhaka"),
			District:     stringPtr("Dhaka"),
			Status:       stringPtr("active"),
			IsOpen:       stringPtr("yes"),
			Shift:        stringPtr("morning"),
		},
	}

	for _, branch := range branches {
		if err := db.Create(&branch).Error; err != nil {
			logger.Error("Failed to create post office branch", err)
			return err
		}
	}

	logger.Success("✅ Address hierarchy data seeded successfully")
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
