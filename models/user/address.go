package user

import "time"

type Division struct {
	ID     uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	EnName string `gorm:"size:255;index" json:"en_name"`
	BnName string `gorm:"size:255;index" json:"bn_name"`
	Slug   string `gorm:"size:127;index" json:"slug"`

	Districts []District `gorm:"foreignKey:DivisionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"districts,omitempty"`
}

type District struct {
	ID         uint     `gorm:"primaryKey;autoIncrement" json:"id"`
	DivisionID uint     `gorm:"index;not null" json:"division_id"`
	Division   Division `gorm:"foreignKey:DivisionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"division,omitempty"`

	EnName string `gorm:"size:255;index" json:"en_name"`
	BnName string `gorm:"size:255;index" json:"bn_name"`
	Slug   string `gorm:"size:127;index" json:"slug"`

	PoliceStations []PoliceStation `gorm:"foreignKey:DistrictID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"police_stations,omitempty"`
}

type PoliceStation struct {
	ID         uint     `gorm:"primaryKey;autoIncrement" json:"id"`
	DistrictID uint     `gorm:"index;not null" json:"district_id"`
	District   District `gorm:"foreignKey:DistrictID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"district,omitempty"`

	EnName string `gorm:"size:255;index" json:"en_name"`
	BnName string `gorm:"size:255;index" json:"bn_name"`
	Slug   string `gorm:"size:127;index" json:"slug"`

	PostOffices []PostOffice `gorm:"foreignKey:PoliceStationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"post_offices,omitempty"`
}

type PostOffice struct {
	ID              uint          `gorm:"primaryKey;autoIncrement" json:"id"`
	PoliceStationID uint          `gorm:"index;not null" json:"police_station_id"`
	PoliceStation   PoliceStation `gorm:"foreignKey:PoliceStationID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"police_station,omitempty"`

	EnName   string `gorm:"size:255;index" json:"en_name"`
	BnName   string `gorm:"size:255;index" json:"bn_name"`
	Slug     string `gorm:"size:127;index" json:"slug"`
	PostCode string `gorm:"size:255;index" json:"post_code"` // Postcode

	Branches []PostOfficeBranch `gorm:"foreignKey:PostOfficeID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"branches,omitempty"`
}

type PostOfficeBranch struct {
	ID                 uint        `gorm:"primaryKey;autoIncrement" json:"id"`
	PostOfficeID       *uint       `gorm:"index" json:"post_office_id,omitempty"`
	PostOffice         *PostOffice `gorm:"foreignKey:PostOfficeID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"post_office,omitempty"`
	Slug               *string     `gorm:"size:127;index" json:"slug,omitempty"`
	BranchCode         *string     `gorm:"size:255;index" json:"branch_code,omitempty"`
	Circle             *string     `gorm:"size:255;index" json:"circle,omitempty"`
	CityPost           *string     `gorm:"size:50;index" json:"city_post,omitempty"`
	ControlOffice      *string     `gorm:"size:100;index" json:"control_office,omitempty"`
	Dept               *int        `json:"dept,omitempty"`
	DirectTransportReq *string     `gorm:"size:20;index" json:"direct_transport_req,omitempty"`
	District           *string     `gorm:"size:150;index" json:"district,omitempty"`
	EmtsBranchCode     *string     `gorm:"size:255;index" json:"emts_branch_code,omitempty"`
	IsOpen             *string     `gorm:"size:20;index" json:"is_open,omitempty"`
	Name               *string     `gorm:"size:255;index" json:"name,omitempty"`
	EnName             *string     `gorm:"size:255;index" json:"en_name,omitempty"`
	BnName             *string     `gorm:"size:255;index" json:"bn_name,omitempty"`
	RmsCode            *string     `gorm:"size:255;index" json:"rms_code,omitempty"`
	Shift              *string     `gorm:"size:20;index" json:"shift,omitempty"`
	Status             *string     `gorm:"size:100;index" json:"status,omitempty"`
	Upzilla            *string     `gorm:"size:255;index" json:"upzilla,omitempty"`
}

// TableName specifies the table name for PostOfficeBranch
func (PostOfficeBranch) TableName() string {
	return "post_office_branches"
}

// Address represents sender or recipient address information
type Address struct {
	ID                 uint    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name               *string `gorm:"size:255" json:"name,omitempty"`
	DistrictID         *uint   `gorm:"size:255" json:"district,omitempty"`
	PoliceStationID    *uint   `gorm:"size:255" json:"police_station,omitempty"`
	PostOfficeID       *uint   `gorm:"size:255" json:"post_office_name,omitempty"`
	PostOfficeBranchID *uint   `json:"post_office_code,omitempty"`
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
