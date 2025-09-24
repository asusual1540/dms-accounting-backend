package constants

// Organization permissions
const (
	// Admin permissions
	PermEkdakDPMGFull               = "ekdak.dpmg.full-permit"
	PermEkdakSuperAdminFull         = "ekdak.super-admin.full-permit"
	PermCorporateDPMGFull           = "corporate-booking.dpmg.full-permit"
	PermDMSAccountingSuperAdminFull = "dms-accounting.super-admin.full-permit"
	PermDMSAccountingDPMGFull       = "dms-accounting.dpmg.full-permit"
	PermDMSAccountingPostmasterFull = "dms-accounting.postmaster.full-permit"
	PermPostOfficeAdminFull         = "corporate-booking.post-office-admin.full-permit"
	PermOrgStandardSuperAdminFull   = "corporate-booking.org-standard-super-admin.full-permit"
	PermStandardAdminHasFull        = "corporate-booking.standard-admin.has-full-permit"
	PermStandardOperator            = "corporate-booking.standard-operator.has-permit"

	// // Organization specific permissions
	// PermOrgCreate         = "corporate-booking.org.create"
	// PermOrgRead           = "corporate-booking.org.read"
	// PermOrgUpdate         = "corporate-booking.org.update"
	// PermOrgDelete         = "corporate-booking.org.delete"
	// PermOrgManageStrategy = "corporate-booking.org.manage-strategy"

	// // Booking permissions
	// PermBookingCreate = "corporate-booking.booking.create"
	// PermBookingRead   = "corporate-booking.booking.read"
	// PermBookingUpdate = "corporate-booking.booking.update"
	// PermBookingDelete = "corporate-booking.booking.delete"

	// // User permissions
	// PermUserCreate = "corporate-booking.user.create"
	// PermUserRead   = "corporate-booking.user.read"
	// PermUserUpdate = "corporate-booking.user.update"
	// PermUserDelete = "corporate-booking.user.delete"

	// Special permissions
	PermAny = "any"
)

// Permission groups for convenience
var (
	OrganizationAdminPermissions = []string{
		PermEkdakDPMGFull,
		PermCorporateDPMGFull,
		PermPostOfficeAdminFull,
	}

	OrganizationManagerPermissions = []string{
		PermOrgStandardSuperAdminFull,
		PermStandardAdminHasFull,
	}
	OrganizationDebitPermissions = []string{
		PermStandardOperator,
	}

	// OrganizationBasicPermissions = []string{
	// 	PermOrgRead,
	// }
)
