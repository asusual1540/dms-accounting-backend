package database

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"dms-accounting/logger"
	"dms-accounting/models/account"
	"dms-accounting/models/log"
	"dms-accounting/models/organization"
	"dms-accounting/models/user"
)

var DB *gorm.DB

// InitDB initializes the database connection with auto migration and indexing
func InitDB() (*gorm.DB, error) {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		logger.Error("Error loading .env file", err)
	}

	// Get database configuration from environment variables
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	database := os.Getenv("DB_DATABASE")
	user := os.Getenv("DB_USERNAME")
	password := os.Getenv("DB_PASSWORD")
	sslmode := os.Getenv("DB_SSLMODE") // Optional: "disable", "require", etc.

	// Set default sslmode if not provided
	if sslmode == "" {
		sslmode = "disable"
	}

	// Build PostgreSQL DSN string
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, database, sslmode)

	fmt.Println("DSN:", dsn)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.Error("Failed to connect to the database", err)
		return nil, err
	}
	logger.Success("Successfully connected to the database")

	// Use dynamic migration system instead of simple AutoMigrate
	migrator := NewDynamicMigrator(DB)

	// Detect schema changes
	operations, err := migrator.DetectChanges()
	if err != nil {
		logger.Error("Failed to detect schema changes", err)
		return nil, err
	}

	// Execute migrations
	if err := migrator.ExecuteMigrations(operations); err != nil {
		logger.Error("Failed to execute migrations", err)
		return nil, err
	}
	logger.Success("All dynamic migrations completed successfully")

	// Handle foreign key constraints after migrations
	if err := createForeignKeyConstraints(); err != nil {
		logger.Error("Failed to create foreign key constraints", err)
		return nil, err
	}
	logger.Success("All foreign key constraints created successfully")

	// Create indexes for better performance
	if err := createIndexes(); err != nil {
		logger.Error("Failed to create indexes", err)
		return nil, err
	}
	logger.Success("All indexes created successfully")

	return DB, nil
}

// autoMigrate runs auto migration for all models
func autoMigrate() error {
	// First, migrate models without foreign key constraints in stages

	// Stage 1: Core foundation models
	stage1Models := []interface{}{
		&user.User{},
		&user.Address{},
		&organization.Organization{},
		&organization.OrganizationInfo{},
		&organization.OrganizationUser{},
		&account.AccountOwner{},
	}

	for _, model := range stage1Models {
		if err := DB.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate %T: %w", model, err)
		}
	}

	// Stage 2: Account table without FK constraints to itself
	if err := DB.AutoMigrate(&account.Account{}); err != nil {
		return fmt.Errorf("failed to migrate Account: %w", err)
	}
	// Stage 3: Models that depend on Account but don't have circular dependencies
	stage3Models := []interface{}{
		&account.LedgerUpdateDocument{},
		&account.PostPaidBill{},
	}

	for _, model := range stage3Models {
		if err := DB.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate %T: %w", model, err)
		}
	}

	// Stage 4: AccountLedger with its self-referencing FK constraints
	if err := DB.AutoMigrate(&account.AccountLedger{}); err != nil {
		return fmt.Errorf("failed to migrate AccountLedger: %w", err)
	}

	// Stage 5: Remaining models
	remainingModels := []interface{}{

		// Logging
		&log.Log{},
	}

	for _, model := range remainingModels {
		if err := DB.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate %T: %w", model, err)
		}
	}

	return nil
}

// createIndexes creates additional indexes for better performance
func createIndexes() error {
	// User indexes
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)").Error; err != nil {
		return fmt.Errorf("failed to create user uuid index: %w", err)
	}
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)").Error; err != nil {
		return fmt.Errorf("failed to create user username index: %w", err)
	}
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)").Error; err != nil {
		return fmt.Errorf("failed to create user email index: %w", err)
	}
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)").Error; err != nil {
		return fmt.Errorf("failed to create user phone index: %w", err)
	}
	// if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id)").Error; err != nil {
	// 	return fmt.Errorf("failed to create user organization_id index: %w", err)
	// }

	// Organization indexes
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name)").Error; err != nil {
		return fmt.Errorf("failed to create organization name index: %w", err)
	}
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_organizations_status ON organizations(status)").Error; err != nil {
		return fmt.Errorf("failed to create organization status index: %w", err)
	}

	// Log indexes
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_logs_method ON logs(method)").Error; err != nil {
		return fmt.Errorf("failed to create log method index: %w", err)
	}
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_logs_status_code ON logs(status_code)").Error; err != nil {
		return fmt.Errorf("failed to create log status_code index: %w", err)
	}
	if err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at)").Error; err != nil {
		return fmt.Errorf("failed to create log created_at index: %w", err)
	}

	return nil
}

// createForeignKeyConstraints creates foreign key constraints after auto migration
func createForeignKeyConstraints() error {
	// Define constraints with their names for checking existence
	constraints := []struct {
		name string
		sql  string
	}{
		{
			name: "fk_organizations_created_by",
			sql:  "ALTER TABLE organizations ADD CONSTRAINT fk_organizations_created_by FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL",
		},
		{
			name: "fk_organizations_approved_by",
			sql:  "ALTER TABLE organizations ADD CONSTRAINT fk_organizations_approved_by FOREIGN KEY (approved_by_id) REFERENCES users(id) ON DELETE SET NULL",
		},
	}

	for _, constraint := range constraints {
		// Check if constraint already exists
		var exists bool
		checkSQL := `
			SELECT EXISTS (
				SELECT 1 FROM pg_constraint 
				WHERE conname = $1 
				AND conrelid = (SELECT oid FROM pg_class WHERE relname = 'organizations')
			)`

		err := DB.Raw(checkSQL, constraint.name).Scan(&exists).Error
		if err != nil {
			logger.Warning(fmt.Sprintf("Failed to check constraint existence: %s - Error: %v", constraint.name, err))
			continue
		}

		if !exists {
			if err := DB.Exec(constraint.sql).Error; err != nil {
				logger.Warning(fmt.Sprintf("Failed to create constraint: %s - Error: %v", constraint.name, err))
			} else {
				logger.Success(fmt.Sprintf("Successfully created constraint: %s", constraint.name))
			}
		} else {
			logger.Debug(fmt.Sprintf("Constraint already exists: %s", constraint.name))
		}
	}

	return nil
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// Legacy function for backward compatibility
func ConnectDB() (*gorm.DB, error) {
	return InitDB()
}
