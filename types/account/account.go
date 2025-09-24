package account

// AccountRequest is a struct that represents the request body for creating an account
type AccountCreateRequest struct {
	UserUUID       string  `json:"user_uuid"`
	Currency       string  `json:"currency"`
	AccountType    string  `json:"account_type"`              // personal, organizational, corporate
	MaxLimit       float64 `json:"max_limit"`                 // Maximum limit for the account
	BalanceType    string  `json:"balance_type"`              // e.g., "savings", "current"
	OrganizationID *uint   `json:"organization_id,omitempty"` // For organizational accounts

}
