package account

import (
	"dms-accounting/models/organization"
	"dms-accounting/models/user"
	"time"
)

type Account struct {
	ID uint `gorm:"primaryKey;autoIncrement"`

	AccountNumber   string  `gorm:"size:19;unique;Index;not null"`
	AccountName     *string `gorm:"size:255;index"`
	CurrentBalance  float64 `gorm:"type:decimal(10,2);default:0.00"`
	AccountType     string  `gorm:"size:250;not null;index"` // personal, organizational, corporate
	IsActive        bool    `gorm:"default:false;index"`
	IsLocked        bool    `gorm:"default:false;index"`
	CreatedAt       *time.Time
	UpdatedAt       *time.Time
	MaxLimit        float64 `gorm:"type:decimal(10,2);default:0.00"`
	BalanceType     string  `gorm:"size:255;index"`
	Currency        string  `gorm:"size:3;default:'BDT'"`
	IsSystemAccount bool    `gorm:"default:false"`

	FromBalances []AccountLedger `gorm:"foreignKey:FromAccount;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	ToBalances   []AccountLedger `gorm:"foreignKey:ToAccount;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// Add relationship to AccountOwner
	AccountOwner *AccountOwner `gorm:"foreignKey:AccountID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

type AccountOwner struct {
	ID                 uint  `gorm:"primaryKey;autoIncrement"`
	UserID             *uint `gorm:"index"`
	AdminID            *uint `gorm:"index"`
	AccountID          *uint `gorm:"index;not null"`
	OrgID              *uint `gorm:"index;not null"`
	PostOfficeBranchID *uint `gorm:"index"`

	// Relationships
	User             *user.User                 `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Admin            *user.User                 `gorm:"foreignKey:AdminID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Account          Account                    `gorm:"foreignKey:AccountID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Org              *organization.Organization `gorm:"foreignKey:OrgID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	PostOfficeBranch *user.PostOfficeBranch     `gorm:"foreignKey:PostOfficeBranchID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
}

type PostPaidBill struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	BillUuid string `gorm:"size:36;unique;not null" json:"bill_uuid"`

	Amount float64 `gorm:"type:decimal(10,2);not null"`

	SenderAccountID   *uint  `gorm:"index;not null"`
	ReceiverAccountID *uint  `gorm:"index;not null"`
	ApproverAccountID *uint  `gorm:"index"`
	Reference         string `gorm:"type:text;index"`

	CreatedAt time.Time `gorm:"autoCreateTime"`

	UpdatedAt time.Time `gorm:"autoUpdateTime"`

	IsDelete int `gorm:"default:0"`

	// Relationships
	SenderAccount   *Account `gorm:"foreignKey:SenderAccountID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	ReceiverAccount *Account `gorm:"foreignKey:ReceiverAccountID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	ApproverAccount *Account `gorm:"foreignKey:ApproverAccountID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`
}

type PostPaidBillEvent struct {
	ID             uint         `gorm:"primaryKey;autoIncrement" json:"id"`
	CreatedBy      uint         `gorm:"index;not null" json:"created_by"`
	PostPaidBillID uint         `gorm:"index;not null" json:"post_paid_bill_id"`
	EventType      string       `gorm:"size:100;index;not null" json:"event_type"` // e.g., "created", "sent", "paid", "approved"
	EventTime      time.Time    `gorm:"autoCreateTime" json:"event_time"`
	Notes          *string      `gorm:"type:text" json:"notes,omitempty"`
	CreatedAt      time.Time    `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time    `gorm:"autoUpdateTime" json:"updated_at"`
	CreatedByUser  *user.User   `gorm:"foreignKey:CreatedBy;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT" json:"created_by_user"`
	PostPaidBill   PostPaidBill `gorm:"foreignKey:PostPaidBillID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"post_paid_bill"`
}

type AccountLedger struct {
	ID uint `gorm:"primaryKey;autoIncrement"`
	// Transaction details
	BillID *uint `gorm:"index"` // Optional link to PostPaidBill

	Credit                    *float64 `gorm:"type:decimal(10,2)"`
	Debit                     *float64 `gorm:"type:decimal(10,2)"`
	FromAccountCurrentBalance *float64 `gorm:"type:decimal(10,2)"`
	ToAccountCurrentBalance   *float64 `gorm:"type:decimal(10,2)"`
	Reference                 string   `gorm:"type:text;index"`
	ChallanNo                 *string  `gorm:"size:255;index"`
	Barcode                   *string  `gorm:"size:255;index"`

	OrderID         *uint  `gorm:"index"`
	ToAccount       uint   `gorm:"index"`
	FromAccount     *uint  `gorm:"index"`
	ApprovalStatus  int    `gorm:"default:0"`
	ApprovedBy      *uint  `gorm:"index"`
	VerifiedBy      *uint  `gorm:"index"`
	IsAutoVerified  bool   `gorm:"default:false"`
	StatusActive    int    `gorm:"default:1"`
	IsDelete        int    `gorm:"default:0"`
	TransactionType string `gorm:"size:50;index"` // e.g., "credit", "debit", "refund", "transfer" etc.
	ApprovedAt      *time.Time
	VerifiedAt      *time.Time

	CreatedAt      time.Time `gorm:"autoCreateTime"`
	UpdatedAt      *time.Time
	Approver       *user.User             `gorm:"foreignKey:ApprovedBy;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`
	ToAccountRef   Account                `gorm:"foreignKey:ToAccount;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	FromAccountRef *Account               `gorm:"foreignKey:FromAccount;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Documents      []LedgerUpdateDocument `gorm:"foreignKey:AccountLedgerID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

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
