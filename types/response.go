package types

type ApiResponse struct {
	Message string      `json:"message"`
	Status  int         `json:"status"`
	Token   string      `json:"token,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}
