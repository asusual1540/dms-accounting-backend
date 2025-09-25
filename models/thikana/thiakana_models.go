package thikana

import (
	"gorm.io/gorm"
)

type Division struct {
	gorm.Model
	EnName string `gorm:"size:255;index"`
	BnName string `gorm:"size:255;index"`
	Slug   string `gorm:"size:127;index"`

	Districts []District `gorm:"foreignKey:DivisionID"`
}

type District struct {
	gorm.Model
	DivisionID uint
	Division   Division `gorm:"constraint:OnDelete:CASCADE;"`

	EnName string `gorm:"size:255;index"`
	BnName string `gorm:"size:255;index"`
	Slug   string `gorm:"size:127;index"`

	PoliceStations []PoliceStation `gorm:"foreignKey:DistrictID"`
}

type PoliceStation struct {
	gorm.Model
	DistrictID uint
	District   District `gorm:"constraint:OnDelete:CASCADE;"`

	EnName string `gorm:"size:255;index"`
	BnName string `gorm:"size:255;index"`
	Slug   string `gorm:"size:127;index"`

	PostOffices []PostOffice `gorm:"foreignKey:PoliceStationID"`
}

type PostOffice struct {
	gorm.Model
	PoliceStationID uint
	PoliceStation   PoliceStation `gorm:"constraint:OnDelete:CASCADE;"`

	EnName string `gorm:"size:255;index"`
	BnName string `gorm:"size:255;index"`
	Slug   string `gorm:"size:127;index"`
	Code   string `gorm:"size:255;index"` // Postcode

	Branches []PostOfficeBranch `gorm:"foreignKey:PostOfficeID"`
}

type PostOfficeBranch struct {
	gorm.Model
	PostOfficeID *uint
	PostOffice   *PostOffice `gorm:"constraint:OnDelete:SET NULL;"`

	BranchCode         *string `gorm:"size:255;index"`
	Circle             *string `gorm:"size:255;index"`
	CityPost           *string `gorm:"size:50;index"`
	ControlOffice      *string `gorm:"size:100;index"`
	Dept               *int
	DirectTransportReq *string `gorm:"size:20;index"`
	District           *string `gorm:"size:150;index"`
	EmtsBranchCode     *string `gorm:"size:255;index"`
	IsOpen             *string `gorm:"size:20;index"`
	Name               *string `gorm:"size:255;index"`
	NameUnicode        *string `gorm:"size:255"`
	RmsCode            *string `gorm:"size:255;index"`
	RootPostLevel1     *string `gorm:"size:20;index"`
	RootPostLevel2     *string `gorm:"size:20;index"`
	Shift              *string `gorm:"size:20;index"`
	Status             *string `gorm:"size:100;index"`
	Upzilla            *string `gorm:"size:255;index"`
}
