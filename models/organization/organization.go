package organization

import (
	"dms-accounting/models/user"
	"time"
)

// Organization model
type Organization struct {
	ID           uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	Name         string     `gorm:"size:255;not null" json:"name"`
	Code         string     `gorm:"size:50;not null;unique" json:"code"`
	Type         string     `gorm:"size:100" json:"type"`                            // e.g., "corporate", "government", "ngo"
	Status       string     `gorm:"size:50;not null;default:inactive" json:"status"` // active, inactive, suspended
	IsActive     bool       `gorm:"not null;default:false" json:"is_active"`
	CreatedByID  *uint      `gorm:"index" json:"created_by_id,omitempty"`  // Foreign key to users table
	ApprovedByID *uint      `gorm:"index" json:"approved_by_id,omitempty"` // Foreign key to users table
	ApprovedAt   *time.Time `json:"approved_at,omitempty"`
	CreatedAt    time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt    *time.Time `gorm:"index" json:"deleted_at,omitempty"`

	// Foreign key relationships
	CreatedByUser  *user.User `gorm:"foreignKey:CreatedByID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"created_by_user,omitempty"`
	ApprovedByUser *user.User `gorm:"foreignKey:ApprovedByID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"approved_by_user,omitempty"`

	// Other relationships
	// OrganizationInfo    *OrganizationInfo    `gorm:"foreignKey:OrganizationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"organization_info,omitempty"`
	// GetOrderStrategy    *GetOrderStrategy    `gorm:"foreignKey:OrganizationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"get_order_strategy,omitempty"`
	// UpdateOrderStrategy *UpdateOrderStrategy `gorm:"foreignKey:OrganizationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"update_order_strategy,omitempty"`
}

// OrganizationInfo represents detailed information about an organization
type OrganizationInfo struct {
	ID             uint    `gorm:"primaryKey;autoIncrement" json:"id"`
	OrganizationID uint    `gorm:"not null;unique;index" json:"organization_id"`
	LegalName      string  `gorm:"size:255" json:"legal_name"`
	TradeName      *string `gorm:"size:255" json:"trade_name,omitempty"`
	RegistrationNo *string `gorm:"size:100" json:"registration_no,omitempty"`
	TaxID          *string `gorm:"size:100" json:"tax_id,omitempty"`
	VatRegNo       *string `gorm:"size:100" json:"vat_reg_no,omitempty"`

	// Contact Information
	Email   *string `gorm:"size:255" json:"email,omitempty"`
	Phone   *string `gorm:"size:20" json:"phone,omitempty"`
	Website *string `gorm:"size:255" json:"website,omitempty"`

	// Address Information
	AddressID uint         `gorm:"not null;index" json:"address_id"`
	Address   user.Address `gorm:"foreignKey:AddressID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"address"`

	// Business Information
	Industry      *string    `gorm:"size:100" json:"industry,omitempty"`
	EmployeeCount *int       `json:"employee_count,omitempty"`
	EstablishedAt *time.Time `json:"established_at,omitempty"`
	Description   *string    `gorm:"type:text" json:"description,omitempty"`

	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`

	// Relationships
	Organization Organization `gorm:"foreignKey:OrganizationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"organization"`
}

type OrganizationUser struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	OrganizationID uint      `gorm:"not null;index" json:"organization_id"`
	UserID         uint      `gorm:"not null;index" json:"user_id"`
	Role           string    `gorm:"size:50;default:member" json:"role"` // owner, admin, member, viewer
	CreatedAt      time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	IsActive       bool      `gorm:"not null;default:true" json:"is_active"`
	IsDeleted      bool      `gorm:"not null;default:false" json:"is_deleted"`

	Organization Organization `gorm:"foreignKey:OrganizationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"organization"`
	User         user.User    `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"user"`
}
