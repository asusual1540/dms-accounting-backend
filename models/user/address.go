package user

// Address represents sender or recipient address information
type Address struct {
	ID             uint    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name           *string `gorm:"size:255" json:"name,omitempty"`
	District       *string `gorm:"size:255" json:"district,omitempty"`
	UpazilaThana   *string `gorm:"size:255" json:"upazila_thana,omitempty"`
	PostOfficeName *string `gorm:"size:255" json:"post_office_name,omitempty"`
	PostOfficeCode *int    `json:"post_office_code,omitempty"`
	StreetAddress  *string `gorm:"size:255" json:"street_address,omitempty"`
	Phone          *string `gorm:"size:255" json:"phone,omitempty"`
}

type PostOfficeBranch struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Name     string `gorm:"size:255;not null" json:"name"`
	PostCode int    `json:"post_code"`
}
