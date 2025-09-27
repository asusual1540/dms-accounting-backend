package constants

// Organization permissions
const (
	// Admin permissions
	// Super Admins
	PermEkdakSuperAdminFull         = "ekdak.super-admin.full-permit"
	PermDMSAccountingSuperAdminFull = "dms-accounting.super-admin.full-permit"

	// DPMG Admins
	PermEkdakDPMGFull         = "ekdak.dpmg.full-permit"
	PermCorporateDPMGFull     = "corporate-booking.dpmg.full-permit"
	PermDMSAccountingDPMGFull = "dms-accounting.dpmg.full-permit"

	// Postmaster Admins
	PermDMSAccountingPostmasterFull = "dms-accounting.postmaster.full-permit"
	PermEkdakPostmasterFull         = "ekdak.post-master.full-permit"
	PermPostOfficeAdminFull         = "corporate-booking.post-office-admin.full-permit"

	// Other DMS Operator
	PermDMSAccountingOperatorFull = "dms-accounting.operator.full-permit"
	PermDMSCounterFull            = "dms.counter.has-full-permit"

	// 3rd Party Organization Manager permissions
	PermOrgStandardSuperAdminFull = "corporate-booking.org-standard-super-admin.full-permit"
	PermStandardAdminHasFull      = "corporate-booking.standard-admin.has-full-permit"
	PermStandardOperator          = "corporate-booking.standard-operator.has-permit"

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
		PermCorporateDPMGFull,
		PermStandardAdminHasFull,
	}
	OrganizationDebitPermissions = []string{
		PermStandardOperator,
	}

	PostmasterPermissions = []string{
		PermEkdakPostmasterFull,
		PermDMSAccountingPostmasterFull,
		PermPostOfficeAdminFull,
	}
	AccountingDPMGPermissions = []string{
		PermEkdakDPMGFull,
		PermDMSAccountingDPMGFull,
		PermCorporateDPMGFull,
	}
	AccountingOperatorPermissions = []string{
		PermDMSAccountingOperatorFull,
		PermDMSCounterFull,
	}

	// OrganizationBasicPermissions = []string{
	// 	PermOrgRead,
	// }
)
