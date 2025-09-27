package database

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"dms-accounting/logger"
	"dms-accounting/models/account"
	"dms-accounting/models/log"
	"dms-accounting/models/organization"
	"dms-accounting/models/user"

	"gorm.io/gorm"
)

// ModelInfo represents information about a database model
type ModelInfo struct {
	TableName string
	Model     interface{}
	Fields    []FieldInfo
}

// FieldInfo represents information about a model field
type FieldInfo struct {
	Name          string
	Type          string
	Size          int
	NotNull       bool
	Default       interface{}
	Unique        bool
	Index         bool
	PrimaryKey    bool
	AutoIncrement bool
	ForeignKey    string
	GormTag       string
	JsonTag       string
	// Foreign key constraint details
	ReferencedTable  string
	ReferencedColumn string
	OnUpdate         string
	OnDelete         string
}

// MigrationOperation represents a database migration operation
type MigrationOperation struct {
	Type        string // "add_column", "drop_column", "modify_column", "add_index", "drop_index", "add_constraint", "drop_constraint"
	TableName   string
	ColumnName  string
	OldField    *FieldInfo
	NewField    *FieldInfo
	SQL         string
	Description string
	// Foreign key constraint fields
	ConstraintName   string
	ReferencedTable  string
	ReferencedColumn string
	OnUpdate         string
	OnDelete         string
}

// DynamicMigrator handles dynamic database migrations
type DynamicMigrator struct {
	db     *gorm.DB
	models []ModelInfo
}

// NewDynamicMigrator creates a new dynamic migrator instance
func NewDynamicMigrator(db *gorm.DB) *DynamicMigrator {
	return &DynamicMigrator{
		db:     db,
		models: getRegisteredModels(),
	}
}

// getRegisteredModels returns all registered models for migration
func getRegisteredModels() []ModelInfo {
	models := []interface{}{
		// Core models
		&user.User{},
		&user.Division{},
		&user.District{},
		&user.PoliceStation{},
		&user.PostOffice{},
		&user.PostOfficeBranch{},
		&user.Address{},
		&organization.Organization{},
		&organization.OrganizationInfo{},
		&account.AccountOwner{},
		&organization.OrganizationUser{},

		// Account models
		&account.Account{},
		&account.AccountLedger{},
		&account.LedgerUpdateDocument{},
		&account.PostPaidBill{},
		&account.PostPaidBillEvent{},

		// Log models
		&log.Log{},
	}

	var modelInfos []ModelInfo
	for _, model := range models {
		modelInfo := extractModelInfo(model)
		modelInfos = append(modelInfos, modelInfo)
	}

	return modelInfos
}

// GetRegisteredModels is a public wrapper for getRegisteredModels
func GetRegisteredModels() []ModelInfo {
	return getRegisteredModels()
}

// extractModelInfo extracts field information from a model
func extractModelInfo(model interface{}) ModelInfo {
	modelType := reflect.TypeOf(model).Elem()

	// Get table name from GORM
	stmt := &gorm.Statement{DB: DB}
	stmt.Parse(model)
	tableName := stmt.Schema.Table

	var fields []FieldInfo

	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Skip embedded structs that are not database fields
		if field.Anonymous {
			continue
		}

		fieldInfo := extractFieldInfo(field)
		if fieldInfo.Name != "" {
			fields = append(fields, fieldInfo)
		}
	}

	// Extract foreign key relationships from struct fields
	extractForeignKeyRelationships(modelType, &fields, tableName)

	return ModelInfo{
		TableName: tableName,
		Model:     model,
		Fields:    fields,
	}
}

// extractForeignKeyRelationships extracts foreign key relationships from model struct
func extractForeignKeyRelationships(modelType reflect.Type, fields *[]FieldInfo, _ string) {
	// Map to store table name mappings for different models
	tableNameMap := map[string]string{
		"User":                 "users",
		"Division":             "divisions",
		"District":             "districts",
		"PoliceStation":        "police_stations",
		"PostOffice":           "post_offices",
		"PostOfficeBranch":     "post_office_branches", // Use correct custom table name
		"Address":              "addresses",
		"Organization":         "organizations",
		"OrganizationInfo":     "organization_infos",
		"Account":              "accounts",
		"AccountOwner":         "account_owners",
		"AccountUser":          "account_users",
		"AccountLedger":        "account_ledgers",
		"LedgerUpdateDocument": "ledger_update_documents",
		"ResponseTime":         "response_times",
		"ResponseTimeEvent":    "response_time_events",
		"Log":                  "logs",
	}

	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)
		gormTag := field.Tag.Get("gorm")

		// Skip if no gorm tag or marked as ignored
		if gormTag == "" || gormTag == "-" {
			continue
		}

		// Skip association fields - we only want to process the foreign key fields
		if isGormAssociationField(field, gormTag) {
			// Parse this association field to find foreign key relationships
			var foreignKeyColumn, referencedTable, referencedColumn, onUpdate, onDelete string

			// Extract foreign key column name and constraint details
			tags := strings.Split(gormTag, ";")
			for _, tag := range tags {
				tag = strings.TrimSpace(tag)
				if strings.HasPrefix(tag, "foreignKey:") {
					foreignKeyColumn = strings.TrimPrefix(tag, "foreignKey:")
				} else if strings.HasPrefix(tag, "constraint:") {
					constraintStr := strings.TrimPrefix(tag, "constraint:")
					parts := strings.Split(constraintStr, ",")
					for _, part := range parts {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(part, "OnUpdate:") {
							onUpdate = strings.TrimPrefix(part, "OnUpdate:")
						} else if strings.HasPrefix(part, "OnDelete:") {
							onDelete = strings.TrimPrefix(part, "OnDelete:")
						}
					}
				}
			}

			if foreignKeyColumn != "" {
				// Determine referenced table from field type
				fieldTypeName := field.Type.String()
				if strings.Contains(fieldTypeName, "*") {
					fieldTypeName = strings.TrimPrefix(fieldTypeName, "*")
				}
				if strings.Contains(fieldTypeName, "[]") {
					fieldTypeName = strings.TrimPrefix(fieldTypeName, "[]")
				}

				// Extract type name from package.Type format
				if dotIndex := strings.LastIndex(fieldTypeName, "."); dotIndex != -1 {
					fieldTypeName = fieldTypeName[dotIndex+1:]
				}

				// Get referenced table name
				if mappedTable, exists := tableNameMap[fieldTypeName]; exists {
					referencedTable = mappedTable
				} else {
					// Default conversion: convert to snake_case and pluralize
					referencedTable = toSnakeCase(fieldTypeName) + "s"
				}

				// Default referenced column is usually 'id'
				referencedColumn = "id"

				// Find the foreign key field in our fields slice and update it
				foreignKeyFieldName := toSnakeCase(foreignKeyColumn)
				for j, f := range *fields {
					if f.Name == foreignKeyFieldName {
						(*fields)[j].ReferencedTable = referencedTable
						(*fields)[j].ReferencedColumn = referencedColumn
						(*fields)[j].OnUpdate = onUpdate
						(*fields)[j].OnDelete = onDelete
						break
					}
				}
			}
		}
	}
}

// isGormAssociationField checks if a field is a GORM association (relationship) field
func isGormAssociationField(field reflect.StructField, gormTag string) bool {
	// Check if the field type is a struct or slice of structs (associations)
	fieldType := field.Type

	// Handle pointer types
	if fieldType.Kind() == reflect.Ptr {
		fieldType = fieldType.Elem()
	}

	// Handle slice types (for has-many relationships)
	if fieldType.Kind() == reflect.Slice {
		fieldType = fieldType.Elem()
		// Handle slice of pointers
		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}
	}

	// If the field type is a struct (not a basic type), it's likely an association
	if fieldType.Kind() == reflect.Struct {
		// Exclude time.Time which is a struct but should be stored as a database column
		if fieldType == reflect.TypeOf(time.Time{}) {
			return false
		}

		// Check if it has foreignKey tag (indicates this is an association field)
		if strings.Contains(gormTag, "foreignKey:") {
			return true
		}

		// Check for other association indicators
		if strings.Contains(gormTag, "references:") ||
			strings.Contains(gormTag, "many2many:") ||
			strings.Contains(gormTag, "polymorphic:") ||
			strings.Contains(gormTag, "joinForeignKey:") {
			return true
		}

		// If it's a struct type from our models packages, it's likely an association
		typeName := fieldType.String()
		if strings.Contains(typeName, "user.User") ||
			strings.Contains(typeName, "organization.Organization") ||
			strings.Contains(typeName, "account.Account") ||
			strings.Contains(typeName, "account.UserAccount") ||
			strings.Contains(typeName, "log.Log") {
			return true
		}

		return true // Default: if it's a struct, treat as association
	}

	return false
}

// extractFieldInfo extracts field information from a struct field
func extractFieldInfo(field reflect.StructField) FieldInfo {
	gormTag := field.Tag.Get("gorm")
	jsonTag := field.Tag.Get("json")

	// Skip fields marked with gorm:"-"
	if gormTag == "-" {
		return FieldInfo{}
	}

	// Skip GORM association fields (relationships)
	if isGormAssociationField(field, gormTag) {
		return FieldInfo{}
	}

	fieldInfo := FieldInfo{
		Name:    getFieldName(field.Name, gormTag),
		Type:    getFieldType(field.Type, gormTag),
		GormTag: gormTag,
		JsonTag: jsonTag,
	}

	// Parse GORM tags
	fieldInfo.parseGormTags(gormTag)

	return fieldInfo
}

// getFieldName extracts the database field name
func getFieldName(fieldName, gormTag string) string {
	// Check if column name is specified in gorm tag
	tags := strings.Split(gormTag, ";")
	for _, tag := range tags {
		if strings.HasPrefix(tag, "column:") {
			return strings.TrimPrefix(tag, "column:")
		}
	}

	// Convert to snake_case
	return toSnakeCase(fieldName)
}

// getFieldType determines the database field type
func getFieldType(fieldType reflect.Type, gormTag string) string {
	// Handle pointers
	if fieldType.Kind() == reflect.Ptr {
		fieldType = fieldType.Elem()
	}

	// Check for explicit type in gorm tag
	tags := strings.Split(gormTag, ";")
	for _, tag := range tags {
		if strings.HasPrefix(tag, "type:") {
			return strings.TrimPrefix(tag, "type:")
		}
	}

	// Check if this is an auto-increment field
	isAutoIncrement := false
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "autoIncrement" {
			isAutoIncrement = true
			break
		}
	}

	// Map Go types to PostgreSQL types
	switch fieldType.Kind() {
	case reflect.String:
		// Check for size specification
		for _, tag := range tags {
			if strings.HasPrefix(tag, "size:") {
				size := strings.TrimPrefix(tag, "size:")
				return fmt.Sprintf("varchar(%s)", size)
			}
		}
		return "text"
	case reflect.Int, reflect.Int32:
		if isAutoIncrement {
			return "serial"
		}
		return "integer"
	case reflect.Int64:
		if isAutoIncrement {
			return "bigserial"
		}
		return "bigint"
	case reflect.Uint:
		// uint in Go should map to bigint in PostgreSQL to handle large values
		if isAutoIncrement {
			return "bigserial"
		}
		return "bigint"
	case reflect.Uint32:
		if isAutoIncrement {
			return "bigserial"
		}
		return "bigint"
	case reflect.Uint64:
		if isAutoIncrement {
			return "bigserial"
		}
		return "bigint"
	case reflect.Float32:
		return "real"
	case reflect.Float64:
		return "double precision"
	case reflect.Bool:
		return "boolean"
	default:
		if fieldType == reflect.TypeOf(time.Time{}) {
			return "timestamp"
		}
		return "text"
	}
}

// parseGormTags parses GORM tags and sets field properties
func (fi *FieldInfo) parseGormTags(gormTag string) {
	tags := strings.Split(gormTag, ";")

	for _, tag := range tags {
		tag = strings.TrimSpace(tag)

		switch {
		case tag == "primaryKey":
			fi.PrimaryKey = true
			fi.NotNull = true // Primary keys are always NOT NULL
		case tag == "autoIncrement":
			fi.AutoIncrement = true
		case tag == "not null":
			fi.NotNull = true
		case tag == "unique":
			fi.Unique = true
		case tag == "index":
			fi.Index = true
		case strings.HasPrefix(tag, "size:"):
			fmt.Sscanf(tag, "size:%d", &fi.Size)
		case strings.HasPrefix(tag, "default:"):
			fi.Default = strings.TrimPrefix(tag, "default:")
		case strings.HasPrefix(tag, "foreignKey:"):
			fi.ForeignKey = strings.TrimPrefix(tag, "foreignKey:")
		case strings.HasPrefix(tag, "constraint:"):
			// Parse constraint details: constraint:OnUpdate:CASCADE,OnDelete:SET NULL
			constraintStr := strings.TrimPrefix(tag, "constraint:")
			fi.parseConstraintDetails(constraintStr)
		}
	}
}

// parseConstraintDetails parses foreign key constraint details
func (fi *FieldInfo) parseConstraintDetails(constraintStr string) {
	// Split by comma: OnUpdate:CASCADE,OnDelete:SET NULL
	parts := strings.Split(constraintStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "OnUpdate:") {
			fi.OnUpdate = strings.TrimPrefix(part, "OnUpdate:")
		} else if strings.HasPrefix(part, "OnDelete:") {
			fi.OnDelete = strings.TrimPrefix(part, "OnDelete:")
		}
	}
}

// toSnakeCase converts CamelCase to snake_case
func toSnakeCase(str string) string {
	// Handle common special cases for full words
	switch str {
	case "ID":
		return "id"
	case "URL":
		return "url"
	case "API":
		return "api"
	case "HTTP":
		return "http"
	case "JSON":
		return "json"
	case "XML":
		return "xml"
	case "SQL":
		return "sql"
	case "UUID":
		return "uuid"
	}

	// Handle cases where common acronyms are at the end of a word
	acronyms := []string{"ID", "URL", "API", "HTTP", "JSON", "XML", "SQL", "UUID"}
	for _, acronym := range acronyms {
		if strings.HasSuffix(str, acronym) && len(str) > len(acronym) {
			prefix := str[:len(str)-len(acronym)]
			return toSnakeCase(prefix) + "_" + strings.ToLower(acronym)
		}
	}

	// Handle cases where common acronyms are at the beginning of a word
	for _, acronym := range acronyms {
		if strings.HasPrefix(str, acronym) && len(str) > len(acronym) {
			suffix := str[len(acronym):]
			// Check if the next character is uppercase (indicating start of new word)
			if len(suffix) > 0 && suffix[0] >= 'A' && suffix[0] <= 'Z' {
				return strings.ToLower(acronym) + "_" + toSnakeCase(suffix)
			}
		}
	}

	var result strings.Builder
	for i, r := range str {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('_')
		}
		if r >= 'A' && r <= 'Z' {
			result.WriteRune(r - 'A' + 'a')
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// DetectChanges detects changes between current database schema and model definitions
func (dm *DynamicMigrator) DetectChanges() ([]MigrationOperation, error) {
	var operations []MigrationOperation

	logger.Success("🔍 Starting dynamic migration analysis...")

	for _, modelInfo := range dm.models {
		tableOps, err := dm.analyzeTable(modelInfo)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to analyze table %s", modelInfo.TableName), err)
			continue
		}
		operations = append(operations, tableOps...)
	}

	logger.Success(fmt.Sprintf("📊 Detected %d migration operations", len(operations)))
	return operations, nil
}

// analyzeTable analyzes a single table for changes
func (dm *DynamicMigrator) analyzeTable(modelInfo ModelInfo) ([]MigrationOperation, error) {
	var operations []MigrationOperation

	// Check if table exists
	tableExists, err := dm.tableExists(modelInfo.TableName)
	if err != nil {
		return nil, err
	}

	if !tableExists {
		// Table doesn't exist, create it
		op := MigrationOperation{
			Type:        "create_table",
			TableName:   modelInfo.TableName,
			SQL:         dm.generateCreateTableSQL(modelInfo),
			Description: fmt.Sprintf("Create table %s", modelInfo.TableName),
		}
		operations = append(operations, op)
		return operations, nil
	}

	// Get existing columns
	existingColumns, err := dm.getTableColumns(modelInfo.TableName)
	if err != nil {
		return nil, err
	}

	// Create maps for easier comparison
	existingColMap := make(map[string]ColumnInfo)
	for _, col := range existingColumns {
		existingColMap[col.Name] = col
	}

	modelColMap := make(map[string]FieldInfo)
	for _, field := range modelInfo.Fields {
		modelColMap[field.Name] = field
	}

	// Detect new columns
	for _, field := range modelInfo.Fields {
		if _, exists := existingColMap[field.Name]; !exists {
			// Check if this is a NOT NULL column being added to an existing table
			if field.NotNull && dm.tableHasData(modelInfo.TableName) {
				// Split into multiple operations for NOT NULL columns on tables with data
				operations = append(operations, dm.generateSafeAddColumnOperations(modelInfo.TableName, field)...)
			} else {
				// Safe to add normally
				op := MigrationOperation{
					Type:        "add_column",
					TableName:   modelInfo.TableName,
					ColumnName:  field.Name,
					NewField:    &field,
					SQL:         dm.generateAddColumnSQL(modelInfo.TableName, field),
					Description: fmt.Sprintf("Add column %s.%s", modelInfo.TableName, field.Name),
				}
				operations = append(operations, op)
			}
		}
	}

	// Detect removed columns
	for _, col := range existingColumns {
		if _, exists := modelColMap[col.Name]; !exists {
			op := MigrationOperation{
				Type:        "drop_column",
				TableName:   modelInfo.TableName,
				ColumnName:  col.Name,
				SQL:         dm.generateDropColumnSQL(modelInfo.TableName, col.Name),
				Description: fmt.Sprintf("Drop column %s.%s", modelInfo.TableName, col.Name),
			}
			operations = append(operations, op)
		}
	}

	// Detect modified columns
	for _, field := range modelInfo.Fields {
		if existingCol, exists := existingColMap[field.Name]; exists {
			// Skip modification of primary key columns as they can't be altered easily
			if existingCol.IsPrimaryKey || field.PrimaryKey {
				continue
			}

			if dm.isColumnModified(existingCol, field) {
				oldField := dm.convertColumnToField(existingCol)
				op := MigrationOperation{
					Type:        "modify_column",
					TableName:   modelInfo.TableName,
					ColumnName:  field.Name,
					OldField:    &oldField,
					NewField:    &field,
					SQL:         dm.generateModifyColumnSQL(modelInfo.TableName, field),
					Description: fmt.Sprintf("Modify column %s.%s", modelInfo.TableName, field.Name),
				}
				operations = append(operations, op)
			}
		}
	}

	// Detect foreign key constraints
	fkOps, err := dm.analyzeForeignKeyConstraints(modelInfo)
	if err != nil {
		return nil, err
	}
	operations = append(operations, fkOps...)

	// Detect unique constraint changes
	uniqueOps, err := dm.analyzeUniqueConstraints(modelInfo)
	if err != nil {
		return nil, err
	}
	operations = append(operations, uniqueOps...)

	return operations, nil
}

// ensurePrimaryKeyExists ensures that a referenced table has a primary key constraint
func (dm *DynamicMigrator) ensurePrimaryKeyExists(tableName, columnName string) error {
	// First check if the table exists
	var tableExists bool
	err := dm.db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_name = ?
		)`, tableName).Scan(&tableExists).Error

	if err != nil {
		return err
	}

	// If table doesn't exist, skip primary key check
	if !tableExists {
		logger.Debug(fmt.Sprintf("Table %s does not exist, skipping primary key constraint check", tableName))
		return nil
	}

	// Check if primary key constraint exists
	var hasConstraint bool
	err = dm.db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.table_constraints 
			WHERE table_name = ? 
			AND constraint_type = 'PRIMARY KEY'
		)`, tableName).Scan(&hasConstraint).Error

	if err != nil {
		return err
	}

	if !hasConstraint {
		// Add primary key constraint
		sql := fmt.Sprintf(`ALTER TABLE "%s" ADD CONSTRAINT "%s_pkey" PRIMARY KEY ("%s")`,
			tableName, tableName, columnName)

		logger.Debug(fmt.Sprintf("Adding missing primary key constraint to %s.%s", tableName, columnName))
		return dm.db.Exec(sql).Error
	}

	return nil
}

// analyzeForeignKeyConstraints analyzes foreign key constraints for a table
func (dm *DynamicMigrator) analyzeForeignKeyConstraints(modelInfo ModelInfo) ([]MigrationOperation, error) {
	var operations []MigrationOperation

	// Get existing foreign key constraints
	existingConstraints, err := dm.getForeignKeyConstraints(modelInfo.TableName)
	if err != nil {
		return nil, err
	}

	// Create map of existing constraints
	existingConstraintMap := make(map[string]ForeignKeyConstraint)
	for _, constraint := range existingConstraints {
		key := fmt.Sprintf("%s->%s.%s", constraint.ColumnName, constraint.ReferencedTable, constraint.ReferencedColumn)
		existingConstraintMap[key] = constraint
	}

	// Check for missing foreign key constraints
	for _, field := range modelInfo.Fields {
		if field.ReferencedTable != "" && field.ReferencedColumn != "" {
			constraintKey := fmt.Sprintf("%s->%s.%s", field.Name, field.ReferencedTable, field.ReferencedColumn)

			if _, exists := existingConstraintMap[constraintKey]; !exists {
				// Ensure the referenced table has a primary key constraint
				err := dm.ensurePrimaryKeyExists(field.ReferencedTable, field.ReferencedColumn)
				if err != nil {
					logger.Warning(fmt.Sprintf("Failed to ensure primary key exists for %s.%s: %v",
						field.ReferencedTable, field.ReferencedColumn, err))
					continue // Skip this foreign key constraint
				}

				// Missing foreign key constraint - add it
				constraintName := fmt.Sprintf("fk_%s_%s", modelInfo.TableName, field.Name)
				op := MigrationOperation{
					Type:             "add_constraint",
					TableName:        modelInfo.TableName,
					ColumnName:       field.Name,
					ConstraintName:   constraintName,
					ReferencedTable:  field.ReferencedTable,
					ReferencedColumn: field.ReferencedColumn,
					OnUpdate:         field.OnUpdate,
					OnDelete:         field.OnDelete,
					SQL:              dm.generateAddForeignKeySQL(modelInfo.TableName, field, constraintName),
					Description:      fmt.Sprintf("Add foreign key constraint %s.%s -> %s.%s", modelInfo.TableName, field.Name, field.ReferencedTable, field.ReferencedColumn),
				}
				operations = append(operations, op)
			}
		}
	}

	return operations, nil
}

// analyzeUniqueConstraints analyzes unique constraints for a table
func (dm *DynamicMigrator) analyzeUniqueConstraints(modelInfo ModelInfo) ([]MigrationOperation, error) {
	var operations []MigrationOperation

	// Get existing unique constraints
	existingConstraints, err := dm.getUniqueConstraints(modelInfo.TableName)
	if err != nil {
		return nil, err
	}

	// Create map of existing constraints
	existingConstraintMap := make(map[string]bool)
	for _, constraint := range existingConstraints {
		existingConstraintMap[constraint] = true
	}

	// Check for missing unique constraints
	for _, field := range modelInfo.Fields {
		if field.Unique {
			if !existingConstraintMap[field.Name] {
				// Missing unique constraint - add it
				constraintName := fmt.Sprintf("uq_%s_%s", modelInfo.TableName, field.Name)
				op := MigrationOperation{
					Type:           "add_constraint",
					TableName:      modelInfo.TableName,
					ColumnName:     field.Name,
					ConstraintName: constraintName,
					SQL:            dm.generateAddUniqueConstraintSQL(modelInfo.TableName, field.Name, constraintName),
					Description:    fmt.Sprintf("Add unique constraint %s.%s", modelInfo.TableName, field.Name),
				}
				operations = append(operations, op)
			}
		}
	}

	// Check for unique constraints that should be removed
	for columnName := range existingConstraintMap {
		shouldHaveUnique := false
		for _, field := range modelInfo.Fields {
			if field.Name == columnName && field.Unique {
				shouldHaveUnique = true
				break
			}
		}

		if !shouldHaveUnique {
			// Remove unique constraint
			constraintName := fmt.Sprintf("uq_%s_%s", modelInfo.TableName, columnName)
			op := MigrationOperation{
				Type:           "drop_constraint",
				TableName:      modelInfo.TableName,
				ColumnName:     columnName,
				ConstraintName: constraintName,
				SQL:            dm.generateDropUniqueConstraintSQL(modelInfo.TableName, constraintName),
				Description:    fmt.Sprintf("Drop unique constraint %s.%s", modelInfo.TableName, columnName),
			}
			operations = append(operations, op)
		}
	}

	return operations, nil
}

// getUniqueConstraints retrieves existing unique constraints for a table
func (dm *DynamicMigrator) getUniqueConstraints(tableName string) ([]string, error) {
	var constraints []string

	rows, err := dm.db.Raw(`
		SELECT kcu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu 
			ON tc.constraint_name = kcu.constraint_name
		WHERE tc.constraint_type = 'UNIQUE' 
			AND tc.table_name = ?
			AND kcu.table_name = ?
		ORDER BY kcu.column_name
	`, tableName, tableName).Rows()

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var columnName string
		err := rows.Scan(&columnName)
		if err != nil {
			return nil, err
		}
		constraints = append(constraints, columnName)
	}

	return constraints, nil
}

// generateAddUniqueConstraintSQL generates SQL for adding a unique constraint
func (dm *DynamicMigrator) generateAddUniqueConstraintSQL(tableName, columnName, constraintName string) string {
	return fmt.Sprintf(`ALTER TABLE "%s" ADD CONSTRAINT "%s" UNIQUE ("%s")`, tableName, constraintName, columnName)
}

// generateDropUniqueConstraintSQL generates SQL for dropping a unique constraint
func (dm *DynamicMigrator) generateDropUniqueConstraintSQL(tableName, constraintName string) string {
	return fmt.Sprintf(`ALTER TABLE "%s" DROP CONSTRAINT "%s"`, tableName, constraintName)
}

// ForeignKeyConstraint represents an existing foreign key constraint
type ForeignKeyConstraint struct {
	ConstraintName   string
	TableName        string
	ColumnName       string
	ReferencedTable  string
	ReferencedColumn string
	OnUpdate         string
	OnDelete         string
}

// getForeignKeyConstraints retrieves existing foreign key constraints for a table
func (dm *DynamicMigrator) getForeignKeyConstraints(tableName string) ([]ForeignKeyConstraint, error) {
	var constraints []ForeignKeyConstraint

	rows, err := dm.db.Raw(`
		SELECT 
			tc.constraint_name,
			tc.table_name,
			kcu.column_name,
			ccu.table_name AS referenced_table,
			ccu.column_name AS referenced_column,
			rc.update_rule AS on_update,
			rc.delete_rule AS on_delete
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu 
			ON tc.constraint_name = kcu.constraint_name
		JOIN information_schema.constraint_column_usage ccu 
			ON ccu.constraint_name = tc.constraint_name
		JOIN information_schema.referential_constraints rc
			ON tc.constraint_name = rc.constraint_name
		WHERE tc.constraint_type = 'FOREIGN KEY' 
			AND tc.table_name = ?
		ORDER BY tc.constraint_name
	`, tableName).Rows()

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var constraint ForeignKeyConstraint
		err := rows.Scan(
			&constraint.ConstraintName,
			&constraint.TableName,
			&constraint.ColumnName,
			&constraint.ReferencedTable,
			&constraint.ReferencedColumn,
			&constraint.OnUpdate,
			&constraint.OnDelete,
		)
		if err != nil {
			return nil, err
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// generateAddForeignKeySQL generates SQL for adding a foreign key constraint
func (dm *DynamicMigrator) generateAddForeignKeySQL(tableName string, field FieldInfo, constraintName string) string {
	sql := fmt.Sprintf(`ALTER TABLE "%s" ADD CONSTRAINT "%s" FOREIGN KEY ("%s") REFERENCES "%s"("%s")`,
		tableName, constraintName, field.Name, field.ReferencedTable, field.ReferencedColumn)

	if field.OnUpdate != "" {
		sql += fmt.Sprintf(" ON UPDATE %s", field.OnUpdate)
	}

	if field.OnDelete != "" {
		sql += fmt.Sprintf(" ON DELETE %s", field.OnDelete)
	}

	return sql
}

// ColumnInfo represents information about an existing database column
type ColumnInfo struct {
	Name         string
	Type         string
	IsNullable   bool
	Default      interface{}
	IsPrimaryKey bool
}

// tableExists checks if a table exists in the database
func (dm *DynamicMigrator) tableExists(tableName string) (bool, error) {
	var exists bool
	err := dm.db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = CURRENT_SCHEMA() 
			AND table_name = ?
			AND table_type = 'BASE TABLE'
		)`, tableName).Scan(&exists).Error
	return exists, err
}

// getTableColumns retrieves column information for a table
func (dm *DynamicMigrator) getTableColumns(tableName string) ([]ColumnInfo, error) {
	var columns []ColumnInfo

	rows, err := dm.db.Raw(`
		SELECT 
			c.column_name,
			c.data_type,
			c.is_nullable = 'YES' as is_nullable,
			c.column_default,
			CASE WHEN pk.column_name IS NOT NULL THEN true ELSE false END as is_primary_key
		FROM information_schema.columns c
		LEFT JOIN (
			SELECT ku.column_name
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage ku
				ON tc.constraint_name = ku.constraint_name
			WHERE tc.table_name = ? AND tc.constraint_type = 'PRIMARY KEY'
		) pk ON c.column_name = pk.column_name
		WHERE c.table_name = ?
		ORDER BY c.ordinal_position
	`, tableName, tableName).Rows()

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var col ColumnInfo
		var defaultVal interface{}

		err := rows.Scan(&col.Name, &col.Type, &col.IsNullable, &defaultVal, &col.IsPrimaryKey)
		if err != nil {
			return nil, err
		}

		col.Default = defaultVal
		columns = append(columns, col)
	}

	return columns, nil
}

// isColumnModified checks if a column has been modified
func (dm *DynamicMigrator) isColumnModified(existingCol ColumnInfo, field FieldInfo) bool {
	var changes []string

	// Normalize types for comparison
	existingType := dm.normalizeType(existingCol.Type)
	fieldType := dm.normalizeExpectedType(field.Type)

	// Check type changes
	if existingType != fieldType {
		changes = append(changes, fmt.Sprintf("type: %s -> %s", existingType, fieldType))
	}

	// Check nullability changes
	if existingCol.IsNullable == field.NotNull {
		changes = append(changes, fmt.Sprintf("nullable: %v -> %v", existingCol.IsNullable, !field.NotNull))
	}

	// Check default value changes
	if dm.hasDefaultValueChanged(existingCol, field) {
		existingDefault := dm.normalizeDefaultValue(existingCol.Default)
		fieldDefault := ""
		if field.Default != nil {
			fieldDefault = strings.Trim(dm.formatDefaultValue(field.Default, field.Type), "'")
		}
		changes = append(changes, fmt.Sprintf("default: '%s' -> '%s'", existingDefault, fieldDefault))
	}

	if len(changes) > 0 {
		logger.Debug(fmt.Sprintf("Column %s changes detected: %s", field.Name, strings.Join(changes, ", ")))
		return true
	}

	return false
}

// hasDefaultValueChanged checks if default value has changed
func (dm *DynamicMigrator) hasDefaultValueChanged(existingCol ColumnInfo, field FieldInfo) bool {
	// Normalize existing default value
	existingDefault := dm.normalizeDefaultValue(existingCol.Default)

	// Normalize field default value
	fieldDefault := ""
	if field.Default != nil {
		fieldDefault = strings.Trim(dm.formatDefaultValue(field.Default, field.Type), "'")
	}

	// Compare normalized values
	changed := existingDefault != fieldDefault
	if changed {
		logger.Debug(fmt.Sprintf("Default value comparison for %s: existing='%s', model='%s'",
			field.Name, existingDefault, fieldDefault))
	}
	return changed
}

// normalizeDefaultValue normalizes database default values for comparison
func (dm *DynamicMigrator) normalizeDefaultValue(defaultValue interface{}) string {
	if defaultValue == nil {
		return ""
	}

	defaultStr := fmt.Sprintf("%v", defaultValue)

	// Remove common PostgreSQL default value prefixes/suffixes
	defaultStr = strings.TrimSpace(defaultStr)

	// Remove PostgreSQL type casts
	if strings.HasSuffix(defaultStr, "::text") {
		defaultStr = strings.TrimSuffix(defaultStr, "::text")
	}
	if strings.HasSuffix(defaultStr, "::character varying") {
		defaultStr = strings.TrimSuffix(defaultStr, "::character varying")
	}
	if strings.HasSuffix(defaultStr, "::varchar") {
		defaultStr = strings.TrimSuffix(defaultStr, "::varchar")
	}
	if strings.HasSuffix(defaultStr, "::boolean") {
		defaultStr = strings.TrimSuffix(defaultStr, "::boolean")
	}

	// Remove surrounding quotes if present
	if strings.HasPrefix(defaultStr, "'") && strings.HasSuffix(defaultStr, "'") {
		defaultStr = strings.Trim(defaultStr, "'")
	}

	// Handle boolean values
	if defaultStr == "true" || defaultStr == "false" {
		return defaultStr
	}

	return defaultStr
}

// normalizeExpectedType normalizes GORM/Go model field types for PostgreSQL
func (dm *DynamicMigrator) normalizeExpectedType(fieldType string) string {
	fieldType = strings.ToLower(strings.TrimSpace(fieldType))

	// Handle direct PostgreSQL types first (from getFieldType function)
	switch {
	// Serial types (auto-increment)
	case fieldType == "serial" || fieldType == "serial4":
		return "integer"
	case fieldType == "bigserial" || fieldType == "serial8":
		return "bigint"
	case fieldType == "smallserial" || fieldType == "serial2":
		return "smallint"

	// Direct PostgreSQL types
	case fieldType == "integer" || fieldType == "int4":
		return "integer"
	case fieldType == "bigint" || fieldType == "int8":
		return "bigint"
	case fieldType == "smallint" || fieldType == "int2":
		return "smallint"
	case fieldType == "real" || fieldType == "float4":
		return "real"
	case fieldType == "double precision" || fieldType == "float8":
		return "double precision"
	case fieldType == "boolean" || fieldType == "bool":
		return "boolean"
	case fieldType == "text":
		return "text"
	case strings.Contains(fieldType, "varchar"):
		return "varchar"
	case strings.Contains(fieldType, "timestamp"):
		if strings.Contains(fieldType, "with time zone") {
			return "timestamptz"
		}
		return "timestamp"
	case fieldType == "date":
		return "date"
	case fieldType == "time":
		return "time"
	case fieldType == "json":
		return "json"
	case fieldType == "jsonb":
		return "jsonb"
	case fieldType == "uuid":
		return "uuid"
	case fieldType == "bytea":
		return "bytea"
	case strings.Contains(fieldType, "decimal") || strings.Contains(fieldType, "numeric"):
		return "decimal"
	}

	// Map Go types to PostgreSQL types (for cases where Go types are passed)
	switch {
	// String types
	case fieldType == "string":
		return "varchar"

	// Integer types
	case fieldType == "int" || fieldType == "int32":
		return "integer"
	case fieldType == "int64" || fieldType == "int8":
		return "bigint"
	case fieldType == "int16":
		return "smallint"

	// Unsigned integers (PostgreSQL doesn't have unsigned, uses bigint)
	case fieldType == "uint" || fieldType == "uint32":
		return "integer"
	case fieldType == "uint64" || fieldType == "uint8" || fieldType == "uint16":
		return "bigint"

	// Float types
	case fieldType == "float32":
		return "real"
	case fieldType == "float64" || fieldType == "float":
		return "double precision"

	// Time types
	case fieldType == "time.time" || fieldType == "datetime":
		return "timestamp"

	// Binary types
	case fieldType == "[]byte" || fieldType == "bytes":
		return "bytea"

	// Array types
	case strings.Contains(fieldType, "[]"):
		return "array"

	// Default case
	default:
		return fieldType
	}
}

// normalizeType normalizes database types for comparison
func (dm *DynamicMigrator) normalizeType(dbType string) string {
	dbType = strings.ToLower(strings.TrimSpace(dbType))

	// Handle PostgreSQL type aliases and variations
	switch {
	// String types
	case strings.Contains(dbType, "varchar") || strings.Contains(dbType, "character varying"):
		return "varchar"
	case strings.Contains(dbType, "character") && !strings.Contains(dbType, "varying"):
		return "varchar"
	case dbType == "text":
		return "text"

	// Integer types (including all uint variants)
	case dbType == "integer" || dbType == "int" || dbType == "int4":
		return "integer"
	case dbType == "bigint" || dbType == "int8":
		return "bigint"
	case dbType == "smallint" || dbType == "int2":
		return "smallint"

	// Auto-increment types (map to their base types for comparison)
	case strings.Contains(dbType, "bigserial") || dbType == "serial8":
		return "bigint"
	case strings.Contains(dbType, "serial") || dbType == "serial4":
		return "integer"
	case strings.Contains(dbType, "smallserial") || dbType == "serial2":
		return "smallint"

	// Decimal/Numeric types
	case strings.Contains(dbType, "decimal") || strings.Contains(dbType, "numeric"):
		return "decimal"
	case dbType == "real" || dbType == "float4":
		return "real"
	case dbType == "double precision" || dbType == "float8":
		return "double precision"
	case dbType == "money":
		return "money"

	// Boolean types
	case dbType == "boolean" || dbType == "bool":
		return "boolean"

	// Date/Time types
	case strings.Contains(dbType, "timestamp"):
		if strings.Contains(dbType, "with time zone") {
			return "timestamptz"
		}
		return "timestamp"
	case strings.Contains(dbType, "time"):
		return "time"
	case dbType == "date":
		return "date"
	case dbType == "interval":
		return "interval"

	// JSON types
	case dbType == "json":
		return "json"
	case dbType == "jsonb":
		return "jsonb"

	// Array types
	case strings.Contains(dbType, "[]"):
		return "array"

	// UUID type
	case dbType == "uuid":
		return "uuid"

	// Binary types
	case dbType == "bytea":
		return "bytea"

	// Network types
	case dbType == "inet":
		return "inet"
	case dbType == "cidr":
		return "cidr"
	case dbType == "macaddr":
		return "macaddr"

	// Geometric types
	case dbType == "point":
		return "point"
	case dbType == "line":
		return "line"
	case dbType == "lseg":
		return "lseg"
	case dbType == "box":
		return "box"
	case dbType == "path":
		return "path"
	case dbType == "polygon":
		return "polygon"
	case dbType == "circle":
		return "circle"

	// Default case - return as is but normalized
	default:
		return dbType
	}
}

// convertColumnToField converts ColumnInfo to FieldInfo
func (dm *DynamicMigrator) convertColumnToField(col ColumnInfo) FieldInfo {
	return FieldInfo{
		Name:       col.Name,
		Type:       col.Type,
		NotNull:    !col.IsNullable,
		Default:    col.Default,
		PrimaryKey: col.IsPrimaryKey,
	}
}

// ExecuteMigrations executes the migration operations
func (dm *DynamicMigrator) ExecuteMigrations(operations []MigrationOperation) error {
	if len(operations) == 0 {
		logger.Success("✅ No migrations needed - database is up to date")
		return nil
	}

	logger.Success(fmt.Sprintf("🚀 Executing %d migration operations...", len(operations)))

	// Execute in transaction
	return dm.db.Transaction(func(tx *gorm.DB) error {
		for i, op := range operations {
			logger.Debug(fmt.Sprintf("[%d/%d] %s", i+1, len(operations), op.Description))

			if err := tx.Exec(op.SQL).Error; err != nil {
				logger.Error(fmt.Sprintf("Failed to execute migration: %s", op.Description), err)
				return err
			}

			logger.Success(fmt.Sprintf("✅ %s", op.Description))
		}
		return nil
	})
}

// formatDefaultValue formats a default value for SQL based on the field type
func (dm *DynamicMigrator) formatDefaultValue(defaultValue interface{}, fieldType string) string {
	if defaultValue == nil {
		return "NULL"
	}

	defaultStr := fmt.Sprintf("%v", defaultValue)

	// Handle string defaults - they need to be quoted
	switch {
	case strings.Contains(fieldType, "varchar") || strings.Contains(fieldType, "text") || strings.Contains(fieldType, "char"):
		return fmt.Sprintf("'%s'", strings.ReplaceAll(defaultStr, "'", "''")) // Escape single quotes
	case strings.Contains(fieldType, "boolean") || fieldType == "bool":
		// Handle boolean defaults
		if defaultStr == "true" || defaultStr == "1" {
			return "true"
		}
		return "false"
	default:
		// Numbers and other types don't need quotes
		return defaultStr
	}
}

// SQL generation methods
func (dm *DynamicMigrator) generateCreateTableSQL(modelInfo ModelInfo) string {
	var columns []string
	var constraints []string
	var primaryKeyColumns []string

	for _, field := range modelInfo.Fields {
		colDef := fmt.Sprintf(`"%s" %s`, field.Name, field.Type)

		// For auto-increment fields (SERIAL/BIGSERIAL), don't add NOT NULL explicitly
		// as these types are implicitly NOT NULL
		if field.NotNull && !field.AutoIncrement {
			colDef += " NOT NULL"
		}

		if field.Default != nil && !field.AutoIncrement {
			defaultValue := dm.formatDefaultValue(field.Default, field.Type)
			colDef += fmt.Sprintf(" DEFAULT %s", defaultValue)
		}

		columns = append(columns, colDef)

		if field.PrimaryKey {
			primaryKeyColumns = append(primaryKeyColumns, fmt.Sprintf(`"%s"`, field.Name))
		}

		if field.Unique {
			constraints = append(constraints, fmt.Sprintf(`UNIQUE ("%s")`, field.Name))
		}
	}

	// Add composite primary key constraint if there are primary key columns
	if len(primaryKeyColumns) > 0 {
		constraints = append(constraints, fmt.Sprintf("PRIMARY KEY (%s)", strings.Join(primaryKeyColumns, ", ")))
	}

	sql := fmt.Sprintf("CREATE TABLE \"%s\" (\n", modelInfo.TableName)
	sql += "  " + strings.Join(columns, ",\n  ")

	if len(constraints) > 0 {
		sql += ",\n  " + strings.Join(constraints, ",\n  ")
	}

	sql += "\n)"

	return sql
}

func (dm *DynamicMigrator) generateAddColumnSQL(tableName string, field FieldInfo) string {
	sql := fmt.Sprintf(`ALTER TABLE "%s" ADD COLUMN "%s" %s`, tableName, field.Name, field.Type)

	if field.NotNull {
		sql += " NOT NULL"
	}

	if field.Default != nil {
		defaultValue := dm.formatDefaultValue(field.Default, field.Type)
		sql += fmt.Sprintf(" DEFAULT %s", defaultValue)
	}

	return sql
}

func (dm *DynamicMigrator) generateDropColumnSQL(tableName, columnName string) string {
	return fmt.Sprintf(`ALTER TABLE "%s" DROP COLUMN "%s"`, tableName, columnName)
}

func (dm *DynamicMigrator) generateModifyColumnSQL(tableName string, field FieldInfo) string {
	var sqlParts []string

	// Change column type
	sqlParts = append(sqlParts, fmt.Sprintf(`ALTER COLUMN "%s" TYPE %s`, field.Name, field.Type))

	// Change nullability
	if field.NotNull {
		sqlParts = append(sqlParts, fmt.Sprintf(`ALTER COLUMN "%s" SET NOT NULL`, field.Name))
	} else {
		sqlParts = append(sqlParts, fmt.Sprintf(`ALTER COLUMN "%s" DROP NOT NULL`, field.Name))
	}

	// Change default value
	if field.Default != nil {
		defaultValue := dm.formatDefaultValue(field.Default, field.Type)
		sqlParts = append(sqlParts, fmt.Sprintf(`ALTER COLUMN "%s" SET DEFAULT %s`, field.Name, defaultValue))
	} else {
		sqlParts = append(sqlParts, fmt.Sprintf(`ALTER COLUMN "%s" DROP DEFAULT`, field.Name))
	}

	return fmt.Sprintf(`ALTER TABLE "%s" %s`, tableName, strings.Join(sqlParts, ", "))
}

// tableHasData checks if a table contains any rows
func (dm *DynamicMigrator) tableHasData(tableName string) bool {
	var count int64
	if err := dm.db.Table(tableName).Count(&count).Error; err != nil {
		// If we can't check, assume it has data to be safe
		logger.Warning(fmt.Sprintf("Could not check row count for table %s: %v", tableName, err))
		return true
	}
	return count > 0
}

// generateSafeAddColumnOperations creates multiple operations to safely add a NOT NULL column
// to a table that already contains data
func (dm *DynamicMigrator) generateSafeAddColumnOperations(tableName string, field FieldInfo) []MigrationOperation {
	var operations []MigrationOperation

	// Step 1: Add column as nullable first
	nullableField := field
	nullableField.NotNull = false

	op1 := MigrationOperation{
		Type:        "add_column",
		TableName:   tableName,
		ColumnName:  field.Name,
		NewField:    &nullableField,
		SQL:         dm.generateAddColumnSQL(tableName, nullableField),
		Description: fmt.Sprintf("Add nullable column %s.%s", tableName, field.Name),
	}
	operations = append(operations, op1)

	// Step 2: Handle default values specially for foreign key columns
	var defaultValue interface{}
	isForeignKeyColumn := field.ReferencedTable != "" || strings.HasSuffix(field.Name, "_id")

	if field.Default != nil {
		defaultValue = field.Default
	} else if isForeignKeyColumn {
		// For foreign key columns, try to find a valid reference
		validRef := dm.getValidForeignKeyReference(field.ReferencedTable)
		if validRef > 0 {
			defaultValue = validRef
		} else {
			// If no valid reference found, let's try to use the first account ID from accounts table
			// This is specifically for the post_paid_bills migration issue
			if tableName == "post_paid_bills" && (strings.Contains(field.Name, "account_id")) {
				validRef = dm.getValidForeignKeyReference("accounts")
				if validRef > 0 {
					defaultValue = validRef
					// Also clean up any existing rows with invalid references
					dm.cleanupInvalidForeignKeyReferences(tableName, field.Name, "accounts")
				} else {
					// If still no valid account, keep as nullable
					logger.Warning(fmt.Sprintf("No valid account reference found for %s.%s, keeping as nullable", tableName, field.Name))
					return operations
				}
			} else {
				// For other foreign key columns, keep as nullable
				logger.Warning(fmt.Sprintf("No valid foreign key reference found for %s.%s, keeping as nullable", tableName, field.Name))
				return operations
			}
		}
	} else {
		// Provide sensible defaults based on field type for non-foreign key columns
		switch {
		case strings.Contains(field.Type, "varchar") || strings.Contains(field.Type, "text"):
			defaultValue = ""
		case strings.Contains(field.Type, "bigint") || strings.Contains(field.Type, "integer"):
			defaultValue = 0
		case strings.Contains(field.Type, "boolean"):
			defaultValue = false
		case strings.Contains(field.Type, "decimal") || strings.Contains(field.Type, "numeric"):
			defaultValue = 0.0
		case strings.Contains(field.Type, "timestamp"):
			defaultValue = "CURRENT_TIMESTAMP"
		default:
			defaultValue = "NULL"
		}
	}

	if defaultValue != "NULL" && defaultValue != nil {
		formattedDefault := dm.formatDefaultValue(defaultValue, field.Type)
		updateSQL := fmt.Sprintf(`UPDATE "%s" SET "%s" = %s WHERE "%s" IS NULL`, tableName, field.Name, formattedDefault, field.Name)

		op2 := MigrationOperation{
			Type:        "update_data",
			TableName:   tableName,
			ColumnName:  field.Name,
			SQL:         updateSQL,
			Description: fmt.Sprintf("Update existing rows in %s.%s with default value", tableName, field.Name),
		}
		operations = append(operations, op2)
	}

	// Step 3: Set column to NOT NULL only if we have valid data
	setNotNullSQL := fmt.Sprintf(`ALTER TABLE "%s" ALTER COLUMN "%s" SET NOT NULL`, tableName, field.Name)

	op3 := MigrationOperation{
		Type:        "modify_column",
		TableName:   tableName,
		ColumnName:  field.Name,
		NewField:    &field,
		SQL:         setNotNullSQL,
		Description: fmt.Sprintf("Set %s.%s to NOT NULL", tableName, field.Name),
	}
	operations = append(operations, op3)

	// Step 4: Add default constraint if specified
	if field.Default != nil {
		defaultValue := dm.formatDefaultValue(field.Default, field.Type)
		setDefaultSQL := fmt.Sprintf(`ALTER TABLE "%s" ALTER COLUMN "%s" SET DEFAULT %s`, tableName, field.Name, defaultValue)

		op4 := MigrationOperation{
			Type:        "modify_column",
			TableName:   tableName,
			ColumnName:  field.Name,
			SQL:         setDefaultSQL,
			Description: fmt.Sprintf("Set default value for %s.%s", tableName, field.Name),
		}
		operations = append(operations, op4)
	}

	return operations
}

// getValidForeignKeyReference tries to find a valid ID from the referenced table
func (dm *DynamicMigrator) getValidForeignKeyReference(tableName string) uint {
	if tableName == "" {
		return 0
	}

	var id uint
	// Try to get the first valid ID from the referenced table
	if err := dm.db.Table(tableName).Select("id").Where("id > 0").Order("id ASC").Limit(1).Scan(&id).Error; err != nil {
		logger.Warning(fmt.Sprintf("Could not find valid reference in table %s: %v", tableName, err))
		return 0
	}

	return id
}

// cleanupInvalidForeignKeyReferences removes or fixes invalid foreign key references
func (dm *DynamicMigrator) cleanupInvalidForeignKeyReferences(tableName, columnName, referencedTable string) {
	// First, try to update rows with 0 or invalid references to use a valid reference
	validRef := dm.getValidForeignKeyReference(referencedTable)
	if validRef > 0 {
		updateSQL := fmt.Sprintf(`UPDATE "%s" SET "%s" = %d WHERE "%s" = 0 OR "%s" IS NULL OR "%s" NOT IN (SELECT id FROM "%s")`,
			tableName, columnName, validRef, columnName, columnName, columnName, referencedTable)

		if err := dm.db.Exec(updateSQL).Error; err != nil {
			logger.Warning(fmt.Sprintf("Could not cleanup invalid foreign key references in %s.%s: %v", tableName, columnName, err))
		} else {
			logger.Success(fmt.Sprintf("Cleaned up invalid foreign key references in %s.%s", tableName, columnName))
		}
	}
}

// RunDynamicMigration is a utility function to run dynamic migration from command line or manually
func RunDynamicMigration() error {
	// Initialize database connection
	db, err := InitDB()
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Create migrator
	migrator := NewDynamicMigrator(db)

	// Detect changes
	operations, err := migrator.DetectChanges()
	if err != nil {
		return fmt.Errorf("failed to detect changes: %w", err)
	}

	// Print operations before executing
	if len(operations) > 0 {
		logger.Success("📋 Migration Plan:")
		for i, op := range operations {
			logger.Debug(fmt.Sprintf("[%d] %s", i+1, op.Description))
			logger.Debug(fmt.Sprintf("    SQL: %s", op.SQL))
		}

		// Ask for confirmation (in production, you might want to add a flag for auto-confirm)
		logger.Warning("⚠️  The above migrations will be executed. Continue? (This is automatic in code)")
	}

	// Execute migrations
	return migrator.ExecuteMigrations(operations)
}

// GenerateMigrationFile generates a migration file with SQL commands (for manual review)
func GenerateMigrationFile(filename string) error {
	// Initialize database connection
	db, err := InitDB()
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Create migrator
	migrator := NewDynamicMigrator(db)

	// Detect changes
	operations, err := migrator.DetectChanges()
	if err != nil {
		return fmt.Errorf("failed to detect changes: %w", err)
	}

	if len(operations) == 0 {
		logger.Success("No migrations needed - database is up to date")
		return nil
	}

	// Generate migration file content
	content := fmt.Sprintf("-- Migration generated on %s\n", time.Now().Format("2006-01-02 15:04:05"))
	content += fmt.Sprintf("-- %d operations detected\n\n", len(operations))

	for i, op := range operations {
		content += fmt.Sprintf("-- [%d] %s\n", i+1, op.Description)
		content += op.SQL + ";\n\n"
	}

	// Write to file
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write migration file: %w", err)
	}

	logger.Success(fmt.Sprintf("Migration file generated: %s", filename))
	return nil
}
