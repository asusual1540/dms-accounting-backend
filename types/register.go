package types

import (
	"regexp"
)

type RegisterUserRequest struct {
	PhoneNumber string `json:"phone_number"` // Field to allow login via email or phone
	Token       string `json:"token"`        // Redirect URL after login
	Password    string `json:"password"`
	Username    string `json:"username"`
	Access      string `json:"access"` // Access token for the user
}
type RegisterUserResponse struct {
	Status  string         `json:"status"`
	Code    int            `json:"code"`
	Message string         `json:"message"`
	User    RegisteredUser `json:"user"`
	Data    map[string]any `json:"data"` // or use json.RawMessage if you want to defer parsing
}

type RegisteredUser struct {
	ID          int     `json:"id"`
	UUID        string  `json:"uuid"`
	Username    string  `json:"username"`
	PhoneNumber string  `json:"phone_number"`
	Email       *string `json:"email"`
	CreatedBy   string  `json:"created_by"`
	LegalName   *string `json:"legal_name"`
	ApprovedBy  string  `json:"approved_by"`
	Avatar      *string `json:"avatar"`
}

// Function to validate phone number
func validatePhoneNumber(phone string) bool {
	// Define the regex pattern
	pattern := `^\+88\d{11}$` // Fixed pattern: +88 followed by exactly 9 digits
	// Compile the regular expression
	re := regexp.MustCompile(pattern)
	// Check if the phone matches the pattern
	return re.MatchString(phone)
}

//	{
//	    "internal_identifier": "ekdak",
//	    "redirect_url": "http://localhost:3004",
//	    "user_type": "customer"
//	}
type GetServiceTokenRequest struct {
	InternalIdentifier string `json:"internal_identifier"` // ekdak
	RedirectURL        string `json:"redirect_url"`        // http://localhost:3004
	UserType           string `json:"user_type"`           // customer
}

// {
//     "redirect_token": "270e64b4-14a3-401e-82aa-c33454f784b4"
// }

type GetServiceTokenResponse struct {
	RedirectToken string `json:"redirect_token"` // 270e64b4-14a3-401e-82aa-c33454f784b4
}

// custom error message
func (r GetServiceTokenRequest) Validate() string {
	// Ensure that login identifier is provided (either email or phone)
	if r.InternalIdentifier == "" {
		return "InternalIdentifier is required"
	}

	// Validate password
	if r.RedirectURL == "" {
		return "RedirectURL is required"
	}
	// Validate password
	if r.UserType == "" {
		return "UserType is required"
	}
	return ""
}

// custom error message
func (r RegisterUserRequest) Validate() string {

	if r.Token == "" {
		return "Email is required"
	}
	if r.PhoneNumber == "" {
		return "Phone is required"
	}
	if !validatePhoneNumber(r.PhoneNumber) {
		return "Phone number is invalid"
	}
	if r.Password == "" {
		return "Password is required"
	}

	return ""
}
