package types

type LoginRequest struct {
	PhoneNumber string `json:"phone_number"` // Field to allow login via email or phone
	Redirect    string `json:"redirect,omitempty"`
	Password    string `json:"password"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type LoginUserResponse struct {
	Status  string        `json:"status"`
	Type    string        `json:"type"`
	Message string        `json:"message"`
	Data    UserLoginData `json:"data"`
	Refresh string        `json:"refresh"`
	Access  string        `json:"access"`
}

type CreatedByData struct {
	UUID        string `json:"uuid"`
	PhoneNumber string `json:"phone_number"`
}

type ApprovedByData struct {
	UUID        string `json:"uuid"`
	PhoneNumber string `json:"phone_number"`
}

type UserLoginData struct {
	TokenType     string          `json:"token_type"`
	Exp           int64           `json:"exp"`
	Iat           int64           `json:"iat"`
	Jti           string          `json:"jti"`
	UUID          string          `json:"uuid"`
	Nonce         int             `json:"nonce"`
	Avatar        string          `json:"avatar"`
	Username      string          `json:"username"`
	LegalName     *string         `json:"legal_name"`
	Phone         string          `json:"phone"`
	PhoneVerified bool            `json:"phone_verified"`
	Email         *string         `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	CreatedBy     *CreatedByData  `json:"created_by"`
	ApprovedBy    *ApprovedByData `json:"approved_by"`
	Permissions   []string        `json:"permissions"`
	Refresh       string          `json:"refresh"`
	Access        string          `json:"access"`
}

// custom error message
func (r LoginRequest) Validate() string {
	// Ensure that login identifier is provided (either email or phone)
	if r.PhoneNumber == "" {
		return "Either email or phone is required"
	}

	// Validate password
	if r.Password == "" {
		return "Password is required"
	}
	return ""
}
