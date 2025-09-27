package database

import (
	"dms-accounting/logger"
	"dms-accounting/models/user"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/gorm"
)

// checkDatabaseVsJSONCounts compares database record counts with JSON object counts
func checkDatabaseVsJSONCounts(db *gorm.DB, jsonDataPath string) (bool, error) {
	// Check divisions (hardcoded to 8 divisions)
	var divisionCount int64
	db.Model(&user.Division{}).Count(&divisionCount)
	if divisionCount < 8 {
		logger.Info(fmt.Sprintf("Database has %d divisions, expected 8. Proceeding with seeding...", divisionCount))
		return false, nil
	}

	// Check districts from division.json
	districtJSONCount, err := countJSONObjects(filepath.Join(jsonDataPath, "division.json"))
	if err != nil {
		return false, fmt.Errorf("failed to count districts in JSON: %w", err)
	}
	var districtCount int64
	db.Model(&user.District{}).Count(&districtCount)
	if int64(districtJSONCount) > districtCount {
		logger.Info(fmt.Sprintf("Database has %d districts, JSON has %d. Proceeding with seeding...", districtCount, districtJSONCount))
		return false, nil
	}

	// Check police stations from police_station.json
	policeStationJSONCount, err := countJSONObjects(filepath.Join(jsonDataPath, "police_station.json"))
	if err != nil {
		return false, fmt.Errorf("failed to count police stations in JSON: %w", err)
	}
	var policeStationCount int64
	db.Model(&user.PoliceStation{}).Count(&policeStationCount)
	if int64(policeStationJSONCount) > policeStationCount {
		logger.Info(fmt.Sprintf("Database has %d police stations, JSON has %d. Proceeding with seeding...", policeStationCount, policeStationJSONCount))
		return false, nil
	}

	// Check post offices from post_office.json
	postOfficeJSONCount, err := countJSONObjects(filepath.Join(jsonDataPath, "post_office.json"))
	if err != nil {
		return false, fmt.Errorf("failed to count post offices in JSON: %w", err)
	}
	var postOfficeCount int64
	db.Model(&user.PostOffice{}).Count(&postOfficeCount)
	if int64(postOfficeJSONCount) > postOfficeCount {
		logger.Info(fmt.Sprintf("Database has %d post offices, JSON has %d. Proceeding with seeding...", postOfficeCount, postOfficeJSONCount))
		return false, nil
	}

	// Check post office branches from post_office_branch.json
	postOfficeBranchJSONCount, err := countJSONObjects(filepath.Join(jsonDataPath, "post_office_branch.json"))
	if err != nil {
		return false, fmt.Errorf("failed to count post office branches in JSON: %w", err)
	}
	var postOfficeBranchCount int64
	db.Model(&user.PostOfficeBranch{}).Count(&postOfficeBranchCount)
	if int64(postOfficeBranchJSONCount) > postOfficeBranchCount {
		logger.Info(fmt.Sprintf("Database has %d post office branches, JSON has %d. Proceeding with seeding...", postOfficeBranchCount, postOfficeBranchJSONCount))
		return false, nil
	}

	logger.Info("Database record counts match JSON object counts for all address data")
	return true, nil
}

// countJSONObjects counts the number of objects in a JSON array file
func countJSONObjects(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var data []interface{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return 0, err
	}

	return len(data), nil
}

// SeedAddressDataFromJSON creates complete address hierarchy data from JSON files
func SeedAddressDataFromJSON(db *gorm.DB) error {
	logger.Info("🌱 Starting to seed address data from JSON files...")

	// Get the project root directory
	projectRoot, err := os.Getwd()
	if err != nil {
		logger.Error("Failed to get current working directory", err)
		return err
	}

	jsonDataPath := filepath.Join(projectRoot, "json_data")

	// Check if database records match JSON object counts
	shouldSkip, err := checkDatabaseVsJSONCounts(db, jsonDataPath)
	if err != nil {
		logger.Error("Failed to check database vs JSON counts", err)
		return err
	}
	if shouldSkip {
		logger.Debug("Database already has all JSON data, skipping...")
		return nil
	}

	// Seed all address data in correct order
	if err := seedDivisionsFromJSON(db, jsonDataPath); err != nil {
		return fmt.Errorf("failed to seed divisions: %w", err)
	}

	if err := seedDistrictsFromJSON(db, jsonDataPath); err != nil {
		return fmt.Errorf("failed to seed districts: %w", err)
	}

	if err := seedPoliceStationsFromJSON(db, jsonDataPath); err != nil {
		return fmt.Errorf("failed to seed police stations: %w", err)
	}

	if err := seedPostOfficesFromJSON(db, jsonDataPath); err != nil {
		return fmt.Errorf("failed to seed post offices: %w", err)
	}

	if err := seedPostOfficeBranchesFromJSON(db, jsonDataPath); err != nil {
		return fmt.Errorf("failed to seed post office branches: %w", err)
	}

	// Validate data integrity after seeding
	if err := ValidateAddressDataIntegrity(db); err != nil {
		logger.Error("Address data integrity validation failed", err)
		return err
	}

	logger.Success("✅ Address hierarchy data seeded successfully from JSON files")
	return nil
}

// ForceReseedAddressData clears existing address data and re-seeds from JSON files
func ForceReseedAddressData(db *gorm.DB) error {
	logger.Warning("⚠️  Force re-seeding address data (this will delete existing data)...")

	// Clear existing data in reverse order (to handle foreign key constraints)
	tables := []string{
		"post_office_branches",
		"post_offices",
		"police_stations",
		"districts",
		"divisions",
	}

	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf("DELETE FROM %s", table)).Error; err != nil {
			logger.Error(fmt.Sprintf("Failed to clear %s", table), err)
			return err
		}
		logger.Info(fmt.Sprintf("✅ Cleared %s", table))
	}

	logger.Info("✅ Cleared all existing address data")

	// Now seed fresh data
	return SeedAddressDataFromJSON(db)
}

// JSON struct definitions for parsing
type AddressDivisionJSON struct {
	ID     uint   `json:"id"`
	EnName string `json:"en_name"`
	BnName string `json:"bn_name"`
	Slug   string `json:"slug"`
}

type AddressDistrictJSON struct {
	ID         uint   `json:"id"`
	EnName     string `json:"en_name"`
	BnName     string `json:"bn_name"`
	Slug       string `json:"slug"`
	DivisionID uint   `json:"division_id"`
}

type AddressPoliceStationJSON struct {
	ID         uint   `json:"id"`
	EnName     string `json:"en_name"`
	BnName     string `json:"bn_name"`
	Slug       string `json:"slug"`
	DistrictID uint   `json:"district_id"`
}

type AddressPostOfficeJSON struct {
	ID              uint   `json:"id"`
	EnName          string `json:"en_name"`
	BnName          string `json:"bn_name"`
	Slug            string `json:"slug"`
	Code            string `json:"code"`
	PoliceStationID uint   `json:"police_station_id"`
}

type AddressPostOfficeBranchJSON struct {
	ID                     uint    `json:"id"`
	BranchCode             *string `json:"branch_code"`
	Circle                 *string `json:"circle"`
	CityPost               *string `json:"city_post"`
	ControlOffice          *string `json:"control_office"`
	Dept                   *int    `json:"dept"`
	DirectTransportRequest *string `json:"direct_transport_request"`
	District               *string `json:"district"`
	EmtsBranchCode         *string `json:"emts_branch_code"`
	IsOpen                 *string `json:"is_open"`
	Name                   *string `json:"name"`
	NameUnicode            *string `json:"name_unicode"`
	RmsCode                *string `json:"rms_code"`
	Shift                  *string `json:"shift"`
	Status                 *string `json:"status"`
	Upzilla                *string `json:"upzilla"`
	PostOfficeID           *uint   `json:"post_office_id"`
}

// seedDivisionsFromJSON creates divisions from the district mapping
func seedDivisionsFromJSON(db *gorm.DB, _ string) error {
	logger.Info("📍 Seeding divisions...")

	// Create the 8 divisions of Bangladesh
	divisions := []user.Division{
		{ID: 1, EnName: "Dhaka", BnName: "ঢাকা", Slug: "dhaka"},
		{ID: 2, EnName: "Chittagong", BnName: "চট্টগ্রাম", Slug: "chittagong"},
		{ID: 3, EnName: "Khulna", BnName: "খুলনা", Slug: "khulna"},
		{ID: 4, EnName: "Rajshahi", BnName: "রাজশাহী", Slug: "rajshahi"},
		{ID: 5, EnName: "Sylhet", BnName: "সিলেট", Slug: "sylhet"},
		{ID: 6, EnName: "Barishal", BnName: "বরিশাল", Slug: "barishal"},
		{ID: 7, EnName: "Mymensingh", BnName: "ময়মনসিংহ", Slug: "mymensingh"},
		{ID: 8, EnName: "Rangpur", BnName: "রংপুর", Slug: "rangpur"},
	}

	// Batch insert with error recovery
	successCount := 0
	for _, div := range divisions {
		if err := db.Create(&div).Error; err != nil {
			logger.Error(fmt.Sprintf("Failed to create division ID %d (%s): %v", div.ID, div.EnName, err), nil)
		} else {
			successCount++
		}
	}

	logger.Success(fmt.Sprintf("✅ Successfully seeded %d/%d divisions", successCount, len(divisions)))
	return nil
}

// seedDistrictsFromJSON reads districts from division.json and seeds them
func seedDistrictsFromJSON(db *gorm.DB, jsonDataPath string) error {
	logger.Info("📍 Seeding districts...")

	file, err := os.Open(filepath.Join(jsonDataPath, "division.json"))
	if err != nil {
		return fmt.Errorf("failed to open division.json: %w", err)
	}
	defer file.Close()

	var districtsData []AddressDistrictJSON
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&districtsData); err != nil {
		return fmt.Errorf("failed to decode division.json: %w", err)
	}

	// Convert to GORM models with correct division mapping
	districts := make([]user.District, len(districtsData))
	for i, dist := range districtsData {
		// Map division_id based on district ID ranges for Bangladesh
		var divisionID uint
		switch {
		case dist.ID >= 1 && dist.ID <= 13:
			divisionID = 1 // Dhaka
		case dist.ID >= 14 && dist.ID <= 24:
			divisionID = 2 // Chittagong
		case dist.ID >= 25 && dist.ID <= 34:
			divisionID = 3 // Khulna
		case dist.ID >= 35 && dist.ID <= 42:
			divisionID = 4 // Rajshahi
		case dist.ID >= 43 && dist.ID <= 46:
			divisionID = 5 // Sylhet
		case dist.ID >= 47 && dist.ID <= 52:
			divisionID = 6 // Barishal
		case dist.ID >= 53 && dist.ID <= 56:
			divisionID = 7 // Mymensingh
		case dist.ID >= 57 && dist.ID <= 64:
			divisionID = 8 // Rangpur
		default:
			divisionID = dist.DivisionID // Fallback to JSON value
		}

		districts[i] = user.District{
			ID:         dist.ID,
			DivisionID: divisionID,
			EnName:     dist.EnName,
			BnName:     dist.BnName,
			Slug:       dist.Slug,
		}
	}

	// Batch insert with error recovery
	batchSize := 100
	successCount := 0
	for i := 0; i < len(districts); i += batchSize {
		end := i + batchSize
		if end > len(districts) {
			end = len(districts)
		}

		batch := districts[i:end]
		if err := db.CreateInBatches(batch, batchSize).Error; err != nil {
			logger.Warning(fmt.Sprintf("Batch insert failed for districts %d-%d, trying individual inserts: %v", i, end, err))
			// Try individual inserts for this batch
			for _, dist := range batch {
				if err := db.Create(&dist).Error; err != nil {
					logger.Error(fmt.Sprintf("Failed to create district ID %d (%s): %v", dist.ID, dist.EnName, err), nil)
				} else {
					successCount++
				}
			}
		} else {
			successCount += len(batch)
		}
	}

	logger.Success(fmt.Sprintf("✅ Successfully seeded %d/%d districts", successCount, len(districts)))
	return nil
}

// seedPoliceStationsFromJSON reads police stations from police_station.json and seeds them
func seedPoliceStationsFromJSON(db *gorm.DB, jsonDataPath string) error {
	logger.Info("📍 Seeding police stations...")

	file, err := os.Open(filepath.Join(jsonDataPath, "police_station.json"))
	if err != nil {
		return fmt.Errorf("failed to open police_station.json: %w", err)
	}
	defer file.Close()

	var policeStationsData []AddressPoliceStationJSON
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&policeStationsData); err != nil {
		return fmt.Errorf("failed to decode police_station.json: %w", err)
	}

	// Convert to GORM models
	policeStations := make([]user.PoliceStation, len(policeStationsData))
	for i, ps := range policeStationsData {
		policeStations[i] = user.PoliceStation{
			ID:         ps.ID,
			DistrictID: ps.DistrictID,
			EnName:     ps.EnName,
			BnName:     ps.BnName,
			Slug:       ps.Slug,
		}
	}

	// Batch insert with error recovery
	batchSize := 100
	successCount := 0
	for i := 0; i < len(policeStations); i += batchSize {
		end := i + batchSize
		if end > len(policeStations) {
			end = len(policeStations)
		}

		batch := policeStations[i:end]
		if err := db.CreateInBatches(batch, batchSize).Error; err != nil {
			logger.Warning(fmt.Sprintf("Batch insert failed for police stations %d-%d, trying individual inserts: %v", i, end, err))
			// Try individual inserts for this batch
			for _, ps := range batch {
				if err := db.Create(&ps).Error; err != nil {
					logger.Error(fmt.Sprintf("Failed to create police station ID %d (%s): %v", ps.ID, ps.EnName, err), nil)
				} else {
					successCount++
				}
			}
		} else {
			successCount += len(batch)
		}
	}

	logger.Success(fmt.Sprintf("✅ Successfully seeded %d/%d police stations", successCount, len(policeStations)))
	return nil
}

// seedPostOfficesFromJSON reads post offices from post_office.json and seeds them
func seedPostOfficesFromJSON(db *gorm.DB, jsonDataPath string) error {
	logger.Info("📍 Seeding post offices...")

	file, err := os.Open(filepath.Join(jsonDataPath, "post_office.json"))
	if err != nil {
		return fmt.Errorf("failed to open post_office.json: %w", err)
	}
	defer file.Close()

	var postOfficesData []AddressPostOfficeJSON
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&postOfficesData); err != nil {
		return fmt.Errorf("failed to decode post_office.json: %w", err)
	}

	// Convert to GORM models
	postOffices := make([]user.PostOffice, len(postOfficesData))
	for i, po := range postOfficesData {
		postOffices[i] = user.PostOffice{
			ID:              po.ID,
			PoliceStationID: po.PoliceStationID,
			EnName:          po.EnName,
			BnName:          po.BnName,
			Slug:            po.Slug,
			PostCode:        po.Code,
		}
	}

	// Batch insert with error recovery in smaller batches due to large size
	batchSize := 50
	successCount := 0
	totalBatches := (len(postOffices) + batchSize - 1) / batchSize

	for i := 0; i < len(postOffices); i += batchSize {
		end := i + batchSize
		if end > len(postOffices) {
			end = len(postOffices)
		}

		batch := postOffices[i:end]
		batchNum := (i / batchSize) + 1

		if err := db.CreateInBatches(batch, batchSize).Error; err != nil {
			logger.Warning(fmt.Sprintf("Batch insert failed for post offices %d-%d, trying individual inserts: %v", i, end, err))
			// Try individual inserts for this batch
			for _, po := range batch {
				if err := db.Create(&po).Error; err != nil {
					logger.Error(fmt.Sprintf("Failed to create post office ID %d (%s): %v", po.ID, po.EnName, err), nil)
				} else {
					successCount++
				}
			}
		} else {
			successCount += len(batch)
		}

		// Log progress for large datasets
		if batchNum%20 == 0 || batchNum == totalBatches {
			logger.Info(fmt.Sprintf("🔄 Processed batch %d/%d (%d/%d post offices)...", batchNum, totalBatches, successCount, len(postOffices)))
		}
	}

	logger.Success(fmt.Sprintf("✅ Successfully seeded %d/%d post offices", successCount, len(postOffices)))
	return nil
}

// seedPostOfficeBranchesFromJSON reads post office branches from post_office_branch.json and seeds them
func seedPostOfficeBranchesFromJSON(db *gorm.DB, jsonDataPath string) error {
	logger.Info("📍 Seeding post office branches...")

	file, err := os.Open(filepath.Join(jsonDataPath, "post_office_branch.json"))
	if err != nil {
		return fmt.Errorf("failed to open post_office_branch.json: %w", err)
	}
	defer file.Close()

	var branchesData []AddressPostOfficeBranchJSON
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&branchesData); err != nil {
		return fmt.Errorf("failed to decode post_office_branch.json: %w", err)
	}

	// Convert to GORM models
	branches := make([]user.PostOfficeBranch, len(branchesData))
	for i, branch := range branchesData {
		branches[i] = user.PostOfficeBranch{
			ID:                 branch.ID,
			PostOfficeID:       branch.PostOfficeID,
			BranchCode:         branch.BranchCode,
			Circle:             branch.Circle,
			CityPost:           branch.CityPost,
			ControlOffice:      branch.ControlOffice,
			Dept:               branch.Dept,
			DirectTransportReq: branch.DirectTransportRequest,
			District:           branch.District,
			EmtsBranchCode:     branch.EmtsBranchCode,
			IsOpen:             branch.IsOpen,
			Name:               branch.Name,
			EnName:             branch.Name, // Using Name as EnName if no separate field
			BnName:             branch.NameUnicode,
			RmsCode:            branch.RmsCode,
			Shift:              branch.Shift,
			Status:             branch.Status,
			Upzilla:            branch.Upzilla,
		}
	}

	// Batch insert with error recovery in smaller batches due to very large size
	batchSize := 25
	successCount := 0
	totalBatches := (len(branches) + batchSize - 1) / batchSize

	for i := 0; i < len(branches); i += batchSize {
		end := i + batchSize
		if end > len(branches) {
			end = len(branches)
		}

		batch := branches[i:end]
		batchNum := (i / batchSize) + 1

		if err := db.CreateInBatches(batch, batchSize).Error; err != nil {
			logger.Warning(fmt.Sprintf("Batch insert failed for post office branches %d-%d, trying individual inserts: %v", i, end, err))
			// Try individual inserts for this batch
			for _, branch := range batch {
				if err := db.Create(&branch).Error; err != nil {
					logger.Error(fmt.Sprintf("Failed to create post office branch ID %d: %v", branch.ID, err), nil)
				} else {
					successCount++
				}
			}
		} else {
			successCount += len(batch)
		}

		// Log progress for very large datasets
		if batchNum%200 == 0 || batchNum == totalBatches {
			logger.Info(fmt.Sprintf("🔄 Processed batch %d/%d (%d/%d post office branches)...", batchNum, totalBatches, successCount, len(branches)))
		}
	}

	logger.Success(fmt.Sprintf("✅ Successfully seeded %d/%d post office branches", successCount, len(branches)))
	return nil
}

// ValidateAddressDataIntegrity checks if all address data was seeded correctly
func ValidateAddressDataIntegrity(db *gorm.DB) error {
	logger.Info("🔍 Validating address data integrity...")

	// Count all entities
	var divisionCount, districtCount, policeStationCount, postOfficeCount, branchCount int64

	db.Model(&user.Division{}).Count(&divisionCount)
	db.Model(&user.District{}).Count(&districtCount)
	db.Model(&user.PoliceStation{}).Count(&policeStationCount)
	db.Model(&user.PostOffice{}).Count(&postOfficeCount)
	db.Model(&user.PostOfficeBranch{}).Count(&branchCount)

	logger.Info(fmt.Sprintf("📊 Address data counts: Divisions: %d, Districts: %d, Police Stations: %d, Post Offices: %d, Branches: %d",
		divisionCount, districtCount, policeStationCount, postOfficeCount, branchCount))

	// Validate relationships
	var orphanedDistricts int64
	db.Model(&user.District{}).
		Joins("LEFT JOIN divisions ON divisions.id = districts.division_id").
		Where("divisions.id IS NULL").
		Count(&orphanedDistricts)

	var orphanedPoliceStations int64
	db.Model(&user.PoliceStation{}).
		Joins("LEFT JOIN districts ON districts.id = police_stations.district_id").
		Where("districts.id IS NULL").
		Count(&orphanedPoliceStations)

	var orphanedPostOffices int64
	db.Model(&user.PostOffice{}).
		Joins("LEFT JOIN police_stations ON police_stations.id = post_offices.police_station_id").
		Where("police_stations.id IS NULL").
		Count(&orphanedPostOffices)

	var orphanedBranches int64
	db.Model(&user.PostOfficeBranch{}).
		Joins("LEFT JOIN post_offices ON post_offices.id = post_office_branches.post_office_id").
		Where("post_offices.id IS NULL AND post_office_branches.post_office_id IS NOT NULL").
		Count(&orphanedBranches)

	if orphanedDistricts > 0 || orphanedPoliceStations > 0 || orphanedPostOffices > 0 || orphanedBranches > 0 {
		return fmt.Errorf("data integrity issues found: orphaned districts: %d, police stations: %d, post offices: %d, branches: %d",
			orphanedDistricts, orphanedPoliceStations, orphanedPostOffices, orphanedBranches)
	}

	logger.Success("✅ Address data integrity validation passed")
	return nil
}
