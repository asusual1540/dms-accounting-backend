package user

import "time"

type Division struct {
	EnName string `gorm:"size:255;index"`
	BnName string `gorm:"size:255;index"`
	Slug   string `gorm:"size:127;index"`

	Districts []District `gorm:"foreignKey:DivisionID"`
}

type District struct {
	DivisionID uint
	Division   Division `gorm:"constraint:OnDelete:CASCADE;"`

	EnName string `gorm:"size:255;index"`
	BnName string `gorm:"size:255;index"`
	Slug   string `gorm:"size:127;index"`

	PoliceStations []PoliceStation `gorm:"foreignKey:DistrictID"`
}

type PoliceStation struct {
	DistrictID uint
	District   District `gorm:"constraint:OnDelete:CASCADE;"`

	EnName string `gorm:"size:255;index"`
	BnName string `gorm:"size:255;index"`
	Slug   string `gorm:"size:127;index"`

	PostOffices []PostOffice `gorm:"foreignKey:PoliceStationID"`
}

type PostOffice struct {
	PoliceStationID uint
	PoliceStation   PoliceStation `gorm:"constraint:OnDelete:CASCADE;"`

	EnName   string `gorm:"size:255;index"`
	BnName   string `gorm:"size:255;index"`
	Slug     string `gorm:"size:127;index"`
	PostCode string `gorm:"size:255;index"` // Postcode

	Branches []PostOfficeBranch `gorm:"foreignKey:PostOfficeID"`
}

type PostOfficeBranch struct {
	PostOfficeID       *uint
	PostOffice         *PostOffice `gorm:"constraint:OnDelete:SET NULL;"`
	Slug               *string     `gorm:"size:127;index"`
	BranchCode         *string     `gorm:"size:255;index"`
	Circle             *string     `gorm:"size:255;index"`
	CityPost           *string     `gorm:"size:50;index"`
	ControlOffice      *string     `gorm:"size:100;index"`
	Dept               *int
	DirectTransportReq *string `gorm:"size:20;index"`
	District           *string `gorm:"size:150;index"`
	EmtsBranchCode     *string `gorm:"size:255;index"`
	IsOpen             *string `gorm:"size:20;index"`
	Name               *string `gorm:"size:255;index"`
	EnName             *string `gorm:"size:255;index"`
	BnName             *string `gorm:"size:255;index"`
	RmsCode            *string `gorm:"size:255;index"`
	Shift              *string `gorm:"size:20;index"`
	Status             *string `gorm:"size:100;index"`
	Upzilla            *string `gorm:"size:255;index"`
}

// Address represents sender or recipient address information
type Address struct {
	ID                 uint    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name               *string `gorm:"size:255" json:"name,omitempty"`
	DistrictID         *uint   `gorm:"size:255" json:"district,omitempty"`
	PoliceStationID    *uint   `gorm:"size:255" json:"police_station,omitempty"`
	PostOfficeID       *uint   `gorm:"size:255" json:"post_office_name,omitempty"`
	PostOfficeBranchID *int    `json:"post_office_code,omitempty"`
	StreetAddress      *string `gorm:"size:255" json:"street_address,omitempty"`
	Phone              *string `gorm:"size:255" json:"phone,omitempty"`

	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt *time.Time `gorm:"autoUpdateTime" json:"updated_at,omitempty"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`

	District         *District         `gorm:"foreignKey:DistrictID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"district_info,omitempty"`
	PoliceStation    *PoliceStation    `gorm:"foreignKey:PoliceStationID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"police_station_info,omitempty"`
	PostOffice       *PostOffice       `gorm:"foreignKey:PostOfficeID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"post_office_info,omitempty"`
	PostOfficeBranch *PostOfficeBranch `gorm:"foreignKey:PostOfficeBranchID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"post_office_branch_info,omitempty"`
}
