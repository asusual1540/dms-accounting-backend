package resource

type ModuleResponse struct {
	ID           uint   `json:"id"`
	Name         string `json:"name"`
	Route        string `json:"route"`
	Permission   string `json:"permission"`
	IsActive     bool   `json:"is_active"`
	Serializable int    `json:"serializable"`
}
