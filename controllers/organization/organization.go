package organization

import (
	"dms-accounting/logger"
	"dms-accounting/models/organization"
	"dms-accounting/models/user"
	"dms-accounting/types"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// Request structures for configuration
type ApiConfigRequest struct {
	ID             *uint    `json:"id,omitempty"`
	BaseURL        string   `json:"base_url" validate:"required"`
	Endpoint       string   `json:"endpoint" validate:"required"`
	Method         string   `json:"method"`
	AuthType       string   `json:"auth_type" validate:"required"`
	AuthToken      *string  `json:"auth_token,omitempty"`
	ApiKey         *string  `json:"api_key,omitempty"`
	ApiKeyHeader   *string  `json:"api_key_header,omitempty"`
	Username       *string  `json:"username,omitempty"`
	Password       *string  `json:"password,omitempty"`
	Headers        []string `json:"headers,omitempty"`
	QueryParams    []string `json:"query_params,omitempty"`
	RequestBody    *string  `json:"request_body,omitempty"`
	TimeoutSeconds *int     `json:"timeout_seconds,omitempty"`
	RetryCount     *int     `json:"retry_count,omitempty"`
	DataPath       *string  `json:"data_path,omitempty"`
}

type ExcelConfigRequest struct {
	ID                *uint    `json:"id,omitempty"`
	TemplateURL       *string  `json:"template_url,omitempty"`
	StartRow          *int     `json:"start_row,omitempty"`
	SheetName         *string  `json:"sheet_name,omitempty"`
	MaxRows           *int     `json:"max_rows,omitempty"`
	AllowedFileTypes  []string `json:"allowed_file_types,omitempty"`
	MaxFileSize       *int64   `json:"max_file_size,omitempty"`
	RequireValidation *bool    `json:"require_validation,omitempty"`
}

type ManualConfigRequest struct {
	ID               *uint    `json:"id,omitempty"`
	RequireApproval  *bool    `json:"require_approval,omitempty"`
	ApprovalWorkflow []string `json:"approval_workflow,omitempty"`
	DefaultValues    []string `json:"default_values,omitempty"`
	RequiredFields   []string `json:"required_fields,omitempty"`
	FormLayout       *string  `json:"form_layout,omitempty"`
}

type WebhookConfigRequest struct {
	ID              *uint    `json:"id,omitempty"`
	WebhookURL      string   `json:"webhook_url" validate:"required"`
	Secret          *string  `json:"secret,omitempty"`
	Headers         []string `json:"headers,omitempty"`
	VerifySignature *bool    `json:"verify_signature,omitempty"`
	SignatureHeader *string  `json:"signature_header,omitempty"`
	EventTypes      []string `json:"event_types,omitempty"`
}

type OrganizationController struct {
	db             *gorm.DB
	loggerInstance *logger.AsyncLogger
}

func NewOrganizationController(db *gorm.DB, loggerInstance *logger.AsyncLogger) *OrganizationController {
	return &OrganizationController{db: db, loggerInstance: loggerInstance}
}

// CreateOrganization creates a new organization or updates existing one if ID is provided
func (o *OrganizationController) CreateOrganization(c *fiber.Ctx) error {
	var req struct {
		ID   *uint  `json:"id,omitempty"`
		Name string `json:"name" validate:"required"`
		Code string `json:"code"`
		Type string `json:"type"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing organization request", err)
		response := types.ApiResponse{
			Message: "Invalid request body",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if req.Name == "" {
		response := types.ApiResponse{
			Message: "Organization name is required",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Get user from middleware
	userClaims := c.Locals("user")
	var createdByID *uint = nil // Default to nil for foreign key

	if userClaims != nil {
		// Try to extract user information from claims
		if claims, ok := userClaims.(map[string]interface{}); ok {
			if userUUID, exists := claims["uuid"]; exists {
				if uuidStr, ok := userUUID.(string); ok {
					// Find user by UUID in database
					var dbUser user.User
					if err := o.db.Where("uuid = ?", uuidStr).First(&dbUser).Error; err == nil {
						createdByID = &dbUser.ID
					} else {
						logger.Error("Error finding user by UUID", err)
					}
				}
			}
		}
	}

	var org organization.Organization
	var isUpdate bool

	if req.ID != nil && *req.ID > 0 {
		// Update existing organization
		if err := o.db.First(&org, *req.ID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				response := types.ApiResponse{
					Message: "Organization not found",
					Status:  fiber.StatusNotFound,
					Data:    nil,
				}
				return c.Status(fiber.StatusNotFound).JSON(response)
			}
			logger.Error("Error fetching organization", err)
			response := types.ApiResponse{
				Message: "Failed to fetch organization",
				Status:  fiber.StatusInternalServerError,
				Data:    nil,
			}
			return c.Status(fiber.StatusInternalServerError).JSON(response)
		}
		isUpdate = true
	} else {
		// Create new organization
		org = organization.Organization{}
	}

	// Set or update fields
	org.Name = req.Name
	if req.Code != "" {
		org.Code = req.Code
	} else if !isUpdate {
		org.Code = o.generateOrgCode(req.Name)
	}

	if req.Type != "" {
		org.Type = req.Type
	} else if !isUpdate {
		org.Type = "corporate"
	}

	// For new organizations, set status to inactive and require approval
	if !isUpdate {
		org.Status = "inactive" // New organizations require approval
		org.IsActive = false    // New organizations are inactive until approved
	}

	// Always set CreatedByID from authenticated user (only for new organizations)
	if !isUpdate {
		org.CreatedByID = createdByID
	}

	var err error
	if isUpdate {
		err = o.db.Save(&org).Error
	} else {
		err = o.db.Create(&org).Error
	}

	if err != nil {
		logger.Error("Error saving organization", err)
		response := types.ApiResponse{
			Message: "Failed to save organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	message := "Organization created successfully and is pending approval"
	status := fiber.StatusCreated
	if isUpdate {
		message = "Organization updated successfully"
		status = fiber.StatusOK
	}

	response := types.ApiResponse{
		Message: message,
		Status:  status,
		Data:    org,
	}
	return c.Status(status).JSON(response)
}

// CreateOrganizationInfo creates or updates organization info
func (o *OrganizationController) CreateOrganizationInfo(c *fiber.Ctx) error {
	var req struct {
		ID             *uint   `json:"id,omitempty"`
		OrganizationID uint    `json:"organization_id" validate:"required"`
		LegalName      string  `json:"legal_name"`
		TradeName      *string `json:"trade_name,omitempty"`
		RegistrationNo *string `json:"registration_no,omitempty"`
		TaxID          *string `json:"tax_id,omitempty"`
		VatRegNo       *string `json:"vat_reg_no,omitempty"`
		Email          *string `json:"email,omitempty"`
		Phone          *string `json:"phone,omitempty"`
		Website        *string `json:"website,omitempty"`
		AddressID      *uint   `json:"address_id,omitempty"`
		Address        *struct {
			ID                 *uint   `json:"id,omitempty"`
			Name               *string `json:"name,omitempty"`
			DistrictID         *uint   `json:"district_id,omitempty"`
			PoliceStationID    *uint   `json:"police_station_id,omitempty"`
			PostOfficeID       *uint   `json:"post_office_id,omitempty"`
			PostOfficeBranchID *uint   `json:"post_office_branch_id,omitempty"`
			StreetAddress      *string `json:"street_address,omitempty"`
			Phone              *string `json:"phone,omitempty"`
		} `json:"address,omitempty"`
		Industry      *string    `json:"industry,omitempty"`
		EmployeeCount *int       `json:"employee_count,omitempty"`
		EstablishedAt *time.Time `json:"established_at,omitempty"`
		Description   *string    `json:"description,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing organization info request", err)
		response := types.ApiResponse{
			Message: "Invalid request body",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if req.OrganizationID == 0 {
		response := types.ApiResponse{
			Message: "Organization ID is required",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Check if organization exists
	var org organization.Organization
	if err := o.db.First(&org, req.OrganizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response := types.ApiResponse{
				Message: "Organization not found",
				Status:  fiber.StatusNotFound,
				Data:    nil,
			}
			return c.Status(fiber.StatusNotFound).JSON(response)
		}
		logger.Error("Error fetching organization", err)
		response := types.ApiResponse{
			Message: "Failed to fetch organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	var orgInfo organization.OrganizationInfo
	var isUpdate bool

	if req.ID != nil && *req.ID > 0 {
		// Update existing organization info
		if err := o.db.First(&orgInfo, *req.ID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				response := types.ApiResponse{
					Message: "Organization info not found",
					Status:  fiber.StatusNotFound,
					Data:    nil,
				}
				return c.Status(fiber.StatusNotFound).JSON(response)
			}
			logger.Error("Error fetching organization info", err)
			response := types.ApiResponse{
				Message: "Failed to fetch organization info",
				Status:  fiber.StatusInternalServerError,
				Data:    nil,
			}
			return c.Status(fiber.StatusInternalServerError).JSON(response)
		}
		isUpdate = true
	} else {
		// Check if organization info already exists for this organization
		if err := o.db.Where("organization_id = ?", req.OrganizationID).First(&orgInfo).Error; err == nil {
			isUpdate = true
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Error checking existing organization info", err)
			response := types.ApiResponse{
				Message: "Failed to check existing organization info",
				Status:  fiber.StatusInternalServerError,
				Data:    nil,
			}
			return c.Status(fiber.StatusInternalServerError).JSON(response)
		}
	}

	// Set or update fields
	orgInfo.OrganizationID = req.OrganizationID
	orgInfo.LegalName = req.LegalName
	orgInfo.TradeName = req.TradeName
	orgInfo.RegistrationNo = req.RegistrationNo
	orgInfo.TaxID = req.TaxID
	orgInfo.VatRegNo = req.VatRegNo
	orgInfo.Email = req.Email
	orgInfo.Phone = req.Phone
	orgInfo.Website = req.Website
	orgInfo.Industry = req.Industry
	orgInfo.EmployeeCount = req.EmployeeCount
	orgInfo.EstablishedAt = req.EstablishedAt
	orgInfo.Description = req.Description

	// Handle address - either use provided AddressID or create new address
	var addressID uint
	if req.AddressID != nil && *req.AddressID > 0 {
		// Use existing address
		addressID = *req.AddressID

		// Verify address exists
		var existingAddress user.Address
		if err := o.db.First(&existingAddress, addressID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				response := types.ApiResponse{
					Message: "Address not found",
					Status:  fiber.StatusNotFound,
					Data:    nil,
				}
				return c.Status(fiber.StatusNotFound).JSON(response)
			}
			logger.Error("Error fetching address", err)
			response := types.ApiResponse{
				Message: "Failed to fetch address",
				Status:  fiber.StatusInternalServerError,
				Data:    nil,
			}
			return c.Status(fiber.StatusInternalServerError).JSON(response)
		}
	} else if req.Address != nil {
		// Create new address or update existing one
		var address user.Address

		if req.Address.ID != nil && *req.Address.ID > 0 {
			// Update existing address
			if err := o.db.First(&address, *req.Address.ID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					response := types.ApiResponse{
						Message: "Address not found",
						Status:  fiber.StatusNotFound,
						Data:    nil,
					}
					return c.Status(fiber.StatusNotFound).JSON(response)
				}
				logger.Error("Error fetching address", err)
				response := types.ApiResponse{
					Message: "Failed to fetch address",
					Status:  fiber.StatusInternalServerError,
					Data:    nil,
				}
				return c.Status(fiber.StatusInternalServerError).JSON(response)
			}
		}

		// Set address fields
		address.Name = req.Address.Name
		address.DistrictID = req.Address.DistrictID
		address.PoliceStationID = req.Address.PoliceStationID
		address.PostOfficeID = req.Address.PostOfficeID
		address.PostOfficeBranchID = req.Address.PostOfficeBranchID
		address.StreetAddress = req.Address.StreetAddress
		address.Phone = req.Address.Phone

		// Save address
		if address.ID == 0 {
			if err := o.db.Create(&address).Error; err != nil {
				logger.Error("Error creating address", err)
				response := types.ApiResponse{
					Message: "Failed to create address",
					Status:  fiber.StatusInternalServerError,
					Data:    nil,
				}
				return c.Status(fiber.StatusInternalServerError).JSON(response)
			}
		} else {
			if err := o.db.Save(&address).Error; err != nil {
				logger.Error("Error updating address", err)
				response := types.ApiResponse{
					Message: "Failed to update address",
					Status:  fiber.StatusInternalServerError,
					Data:    nil,
				}
				return c.Status(fiber.StatusInternalServerError).JSON(response)
			}
		}

		addressID = address.ID
	} else {
		response := types.ApiResponse{
			Message: "Either address_id or address object is required",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Set the address ID
	orgInfo.AddressID = addressID

	var err error
	if isUpdate {
		err = o.db.Save(&orgInfo).Error
	} else {
		err = o.db.Create(&orgInfo).Error
	}

	if err != nil {
		logger.Error("Error saving organization info", err)
		response := types.ApiResponse{
			Message: "Failed to save organization info",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	// Preload the organization and address data for the response
	if err := o.db.Preload("Organization").Preload("Address").First(&orgInfo, orgInfo.ID).Error; err != nil {
		logger.Error("Error preloading organization and address data", err)
		// Continue without preloading if it fails - we'll just have the organization_id and address_id
	}

	message := "Organization info created successfully"
	status := fiber.StatusCreated
	if isUpdate {
		message = "Organization info updated successfully"
		status = fiber.StatusOK
	}

	response := types.ApiResponse{
		Message: message,
		Status:  status,
		Data:    orgInfo,
	}
	return c.Status(status).JSON(response)
}

// GetOrganizations retrieves organizations with pagination
func (o *OrganizationController) GetOrganizations(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	pageSize, _ := strconv.Atoi(c.Query("page_size", "10"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	var total int64
	o.db.Model(&organization.Organization{}).Count(&total)

	offset := (page - 1) * pageSize
	var organizations []organization.Organization
	if err := o.db.Preload("OrganizationInfo.Address").Offset(offset).Limit(pageSize).Find(&organizations).Error; err != nil {
		logger.Error("Error fetching organizations", err)
		response := types.ApiResponse{
			Message: "Failed to fetch organizations",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response := types.ApiResponse{
		Message: "Organizations retrieved successfully",
		Status:  fiber.StatusOK,
		Data: map[string]interface{}{
			"organizations": organizations,
			"total":         total,
			"page":          page,
			"page_size":     pageSize,
			"total_pages":   (total + int64(pageSize) - 1) / int64(pageSize),
		},
	}
	return c.JSON(response)
}

// GetOrganization retrieves a single organization by ID
func (o *OrganizationController) GetOrganization(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		response := types.ApiResponse{
			Message: "Invalid organization ID",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	var org organization.Organization
	if err := o.db.Preload("OrganizationInfo.Address").First(&org, uint(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response := types.ApiResponse{
				Message: "Organization not found",
				Status:  fiber.StatusNotFound,
				Data:    nil,
			}
			return c.Status(fiber.StatusNotFound).JSON(response)
		}
		logger.Error("Error fetching organization", err)
		response := types.ApiResponse{
			Message: "Failed to fetch organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response := types.ApiResponse{
		Message: "Organization retrieved successfully",
		Status:  fiber.StatusOK,
		Data:    org,
	}
	return c.JSON(response)
}

// DeleteOrganization deletes an organization
func (o *OrganizationController) DeleteOrganization(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		response := types.ApiResponse{
			Message: "Invalid organization ID",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Check if organization exists
	var org organization.Organization
	if err := o.db.First(&org, uint(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response := types.ApiResponse{
				Message: "Organization not found",
				Status:  fiber.StatusNotFound,
				Data:    nil,
			}
			return c.Status(fiber.StatusNotFound).JSON(response)
		}
		logger.Error("Error fetching organization", err)
		response := types.ApiResponse{
			Message: "Failed to fetch organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	// Soft delete
	if err := o.db.Delete(&org).Error; err != nil {
		logger.Error("Error deleting organization", err)
		response := types.ApiResponse{
			Message: "Failed to delete organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response := types.ApiResponse{
		Message: "Organization deleted successfully",
		Status:  fiber.StatusOK,
		Data:    nil,
	}
	return c.JSON(response)
}

// Helper function to generate organization code
func (o *OrganizationController) generateOrgCode(name string) string {
	// Create a simple code from the organization name
	parts := strings.Fields(strings.ToUpper(name))
	if len(parts) == 0 {
		return "ORG"
	}

	var code string
	for _, part := range parts {
		if len(part) > 0 {
			code += string(part[0])
		}
		if len(code) >= 3 {
			break
		}
	}

	// Add timestamp to ensure uniqueness
	return code + strconv.FormatInt(time.Now().Unix(), 36)
}

// ApproveOrganization approves an organization by setting status to active and updating approval fields
func (o *OrganizationController) ApproveOrganization(c *fiber.Ctx) error {
	var req struct {
		OrganizationID uint `json:"organization_id" validate:"required"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing approve organization request", err)
		response := types.ApiResponse{
			Message: "Invalid request body",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if req.OrganizationID == 0 {
		response := types.ApiResponse{
			Message: "Organization ID is required",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Get user from middleware
	userClaims := c.Locals("user")
	var approvedByID *uint = nil

	if userClaims != nil {
		// Try to extract user information from claims
		if claims, ok := userClaims.(map[string]interface{}); ok {
			if userUUID, exists := claims["uuid"]; exists {
				if uuidStr, ok := userUUID.(string); ok {
					// Find user by UUID in database
					var dbUser user.User
					if err := o.db.Where("uuid = ?", uuidStr).First(&dbUser).Error; err == nil {
						approvedByID = &dbUser.ID
					} else {
						logger.Error("Error finding user by UUID", err)
						response := types.ApiResponse{
							Message: "Unable to find approving user",
							Status:  fiber.StatusInternalServerError,
							Data:    nil,
						}
						return c.Status(fiber.StatusInternalServerError).JSON(response)
					}
				}
			}
		}
	}

	if approvedByID == nil {
		response := types.ApiResponse{
			Message: "Unable to identify approving user",
			Status:  fiber.StatusUnauthorized,
			Data:    nil,
		}
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	// Find the organization
	var org organization.Organization
	if err := o.db.Where("id = ?", req.OrganizationID).First(&org).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response := types.ApiResponse{
				Message: "Organization not found",
				Status:  fiber.StatusNotFound,
				Data:    nil,
			}
			return c.Status(fiber.StatusNotFound).JSON(response)
		}

		logger.Error("Error finding organization", err)
		response := types.ApiResponse{
			Message: "Error finding organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	// Check if organization is already approved
	if org.Status == "active" && org.IsActive {
		response := types.ApiResponse{
			Message: "Organization is already approved",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Update organization approval fields
	now := time.Now()
	updateData := map[string]interface{}{
		"status":         "active",
		"is_active":      true,
		"approved_by_id": approvedByID,
		"approved_at":    &now,
		"updated_at":     now,
	}

	if err := o.db.Model(&org).Updates(updateData).Error; err != nil {
		logger.Error("Error approving organization", err)
		response := types.ApiResponse{
			Message: "Error approving organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	// Fetch the updated organization with relationships
	if err := o.db.Preload("CreatedByUser").Preload("ApprovedByUser").Where("id = ?", req.OrganizationID).First(&org).Error; err != nil {
		logger.Error("Error fetching updated organization", err)
	}

	response := types.ApiResponse{
		Message: "Organization approved successfully",
		Status:  fiber.StatusOK,
		Data:    org,
	}
	return c.Status(fiber.StatusOK).JSON(response)
}

// OrganizationUser adds a user to an organization
func (o *OrganizationController) CreateOrganizationUser(c *fiber.Ctx) error {
	var req struct {
		OrganizationID uint   `json:"organization_id" validate:"required"`
		UserUid        string `json:"user_uuid" validate:"required"`
	}

	if err := c.BodyParser(&req); err != nil {
		logger.Error("Error parsing organization user request", err)
		response := types.ApiResponse{
			Message: "Invalid request body",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if req.OrganizationID == 0 || req.UserUid == "" {
		response := types.ApiResponse{
			Message: "Organization ID and User ID are required",
			Status:  fiber.StatusBadRequest,
			Data:    nil,
		}
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	var org organization.Organization
	if err := o.db.First(&org, req.OrganizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response := types.ApiResponse{
				Message: "Organization not found",
				Status:  fiber.StatusNotFound,
				Data:    nil,
			}
			return c.Status(fiber.StatusNotFound).JSON(response)
		}
		logger.Error("Error fetching organization", err)
		response := types.ApiResponse{
			Message: "Failed to fetch organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	var user user.User
	if err := o.db.First(&user, req.UserUid).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response := types.ApiResponse{
				Message: "User not found",
				Status:  fiber.StatusNotFound,
				Data:    nil,
			}
			return c.Status(fiber.StatusNotFound).JSON(response)
		}
		logger.Error("Error fetching user", err)
		response := types.ApiResponse{
			Message: "Failed to fetch user",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	orgUser := organization.OrganizationUser{
		OrganizationID: org.ID,
		UserID:         user.ID,
		Role:           "member", // Default role, can be changed later
		IsActive:       true,
		IsDeleted:      false,
	}
	if err := o.db.Create(&orgUser).Error; err != nil {
		logger.Error("Error adding user to organization", err)
		response := types.ApiResponse{
			Message: "Failed to add user to organization",
			Status:  fiber.StatusInternalServerError,
			Data:    nil,
		}
		return c.Status(fiber.StatusInternalServerError).JSON(response)

	}
	response := types.ApiResponse{
		Message: "User added to organization successfully",
		Status:  fiber.StatusOK,
		Data:    orgUser,
	}
	return c.Status(fiber.StatusOK).JSON(response)
}
