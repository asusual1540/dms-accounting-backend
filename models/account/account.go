package account

import (
	"dms-accounting/models/organization"
	"dms-accounting/models/user"
	"time"
)

type Account struct {
	ID uint `gorm:"primaryKey;autoIncrement"`

	AccountNumber   string  `gorm:"size:19;unique;Index;not null"`
	CurrentBalance  float64 `gorm:"type:decimal(10,2);default:0.00"`
	AccountType     string  `gorm:"size:250;not null"` // personal, organizational, corporate
	IsActive        bool    `gorm:"default:true"`
	IsLocked        bool    `gorm:"default:false"`
	CreatedAt       *time.Time
	UpdatedAt       *time.Time
	MaxLimit        float64 `gorm:"type:decimal(10,2);default:0.00"`
	BalanceType     string  `gorm:"size:255"`
	Currency        string  `gorm:"size:3;default:'BDT'"`
	IsSystemAccount bool    `gorm:"default:false"`

	FromBalances []AccountLedger `gorm:"foreignKey:FromAccount;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	ToBalances   []AccountLedger `gorm:"foreignKey:ToAccount;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

type AccountOwner struct {
	ID                 uint  `gorm:"primaryKey;autoIncrement"`
	UserID             *uint `gorm:"index;not null"`
	AccountID          *uint `gorm:"index;not null"`
	OrgID              *uint `gorm:"index;not null"`
	PostOfficeBranchID *uint `gorm:"index"`

	// Relationships
	User             user.User                 `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Account          Account                   `gorm:"foreignKey:AccountID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Org              organization.Organization `gorm:"foreignKey:OrgID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	PostOfficeBranch user.PostOfficeBranch     `gorm:"foreignKey:PostOfficeBranchID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
}

type PostPaidBill struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	BillUuid string `gorm:"size:36;unique;not null" json:"bill_uuid"`

	OrganizationID uint    `gorm:"index;not null"`
	Amount         float64 `gorm:"type:decimal(10,2);not null"`
	IsPaid         bool    `gorm:"default:false"`

	SenderID   uint   `gorm:"index;not null"`
	ReceiverID uint   `gorm:"index;not null"`
	Reference  string `gorm:"type:text"`

	IsApproved bool       `gorm:"default:false"`
	ApprovedAt *time.Time `gorm:"autoCreateTime"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`

	// Relationships
	Organization organization.Organization `gorm:"foreignKey:OrganizationID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Sender       user.User                 `gorm:"foreignKey:SenderID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Receiver     user.User                 `gorm:"foreignKey:ReceiverID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
}

type AccountLedger struct {
	ID uint `gorm:"primaryKey;autoIncrement"`
	// Transaction details
	BillID *uint `gorm:"index"` // Optional link to PostPaidBill

	RecipientID    uint  `gorm:"index;not null"`
	SenderID       uint  `gorm:"index;not null"`
	OrganizationID *uint `gorm:"index"` // For organization-level transactions

	Credit    *float64 `gorm:"type:decimal(10,2)"`
	Debit     *float64 `gorm:"type:decimal(10,2)"`
	Reference string   `gorm:"type:text"`

	OrderID        *uint `gorm:"index"`
	ToAccount      *uint `gorm:"index"`
	FromAccount    *uint `gorm:"index"`
	ApprovalStatus int   `gorm:"default:0"`
	ApprovedBy     *uint `gorm:"index"`
	VerifiedBy     *uint `gorm:"index"`
	IsAutoVerified bool  `gorm:"default:false"`
	StatusActive   int   `gorm:"default:1"`
	IsDelete       int   `gorm:"default:0"`
	ApprovedAt     *time.Time
	VerifiedAt     *time.Time

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt *time.Time

	Recipient      user.User                  `gorm:"foreignKey:RecipientID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Sender         user.User                  `gorm:"foreignKey:SenderID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Organization   *organization.Organization `gorm:"foreignKey:OrganizationID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`
	Approver       *user.User                 `gorm:"foreignKey:ApprovedBy;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`
	ToAccountRef   *Account                   `gorm:"foreignKey:ToAccount;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	FromAccountRef *Account                   `gorm:"foreignKey:FromAccount;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Documents      []LedgerUpdateDocument     `gorm:"foreignKey:AccountLedgerID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	Bill *PostPaidBill `gorm:"foreignKey:BillID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`
}

type LedgerUpdateDocument struct {
	ID              uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	AccountLedgerID uint       `gorm:"index;not null" json:"account_ledger_id"`
	Path            string     `gorm:"size:255;not null" json:"path"`
	CreatedAt       *time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt       *time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	AccountLedger AccountLedger `gorm:"foreignKey:AccountLedgerID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"account_ledger"`
}
