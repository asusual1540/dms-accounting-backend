package httpServices

type ServiceUserRequest struct {
	InternalIdentifier string `json:"internal_identifier"`
	RedirectURL        string `json:"redirect_url"`
	UserType           string `json:"user_type"`
}

type ServiceUserResponse struct {
	RedirectToken string `json:"redirect_token"`
}
