package routes

import (
	"dms-accounting/constants"
	"dms-accounting/controllers/account"
	"dms-accounting/controllers/auth"
	"dms-accounting/controllers/organization"
	"dms-accounting/controllers/user"
	httpServices "dms-accounting/httpServices/sso"
	"dms-accounting/logger"
	"dms-accounting/middleware"
	"os"

	//"dms-accounting/middleware"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func SetupRoutes(app *fiber.App, db *gorm.DB) {
	ssoClient := httpServices.NewClient(os.Getenv("SSO_BASE_URL"))
	asyncLogger := logger.NewAsyncLogger(db)
	authController := auth.NewAuthController(ssoClient, db, asyncLogger)
	orgController := organization.NewOrganizationController(db, asyncLogger)
	accountController := account.NewAccountController(db, asyncLogger)

	// Start the async logger processing goroutine
	go asyncLogger.ProcessLog()

	// Index route
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"title": "Home",
		})
	})

	/*=============================================================================
	| Public Routes
	===============================================================================*/
	api := app.Group("/api")
	api.Post("/get-service-token", authController.GetServiceToken)
	api.Post("/login", authController.Login)

	/*=============================================================================
	| Protected Routes
	===============================================================================*/
	auth := api.Group("/auth").Use(middleware.RequireAnyPermission())
	auth.Post("/register", authController.Register)
	auth.Get("/profile", user.GetUserInfo)
	auth.Post("/logout", authController.LogOut)

	/*============================================================================
	 |organization routes
	==============================================================================*/

	adminGroup := api.Group("/organization")

	/*==============================================================================
	| Account Routes for Post Office Admin
	================================================================================*/
	adminGroup.Post("/account", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), accountController.CreateAccount)

	adminGroup.Get("/account", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), accountController.GetAccounts)
	//
	adminGroup.Get("/account/:id", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), accountController.GetAccount)
	//
	adminGroup.Post("/account/credit", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), accountController.Credit)
	adminGroup.Post("/account/debit", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), accountController.Debit)

	// Debit list of an account and its transactions organization id is required
	adminGroup.Get("/account/debit/:id", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), accountController.GetDebitsByAccountID)

	// ===============================================================================

	adminGroup.Post("/approve", middleware.RequirePermissions(
		constants.PermEkdakDPMGFull,
		constants.PermCorporateDPMGFull,
	), orgController.ApproveOrganization)

	adminGroup.Post("/create", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), orgController.CreateOrganization)

	adminGroup.Post("/info/create", middleware.RequirePermissions(
		constants.PermPostOfficeAdminFull,
	), orgController.CreateOrganizationInfo)

	adminGroup.Delete("/:id", middleware.RequirePermissions(
		constants.PermEkdakDPMGFull,
		constants.PermCorporateDPMGFull,
		constants.PermPostOfficeAdminFull,
		constants.PermStandardOperator,
	), orgController.DeleteOrganization)

	adminGroup.Get("/", middleware.RequirePermissions(
		constants.PermEkdakDPMGFull,
		constants.PermCorporateDPMGFull,
		constants.PermPostOfficeAdminFull,
	), orgController.GetOrganizations)

	adminGroup.Get("/:id", middleware.RequirePermissions(
		constants.PermEkdakDPMGFull,
		constants.PermCorporateDPMGFull,
		constants.PermPostOfficeAdminFull,
		constants.PermStandardOperator,
	), orgController.GetOrganization)

	// Manager routes - requires org manager permissions (admin excluded)
	managerGroup := api.Group("/manage-organization")

	managerGroup.Post("/organizationUser", middleware.RequirePermissions(
		constants.PermOrgStandardSuperAdminFull,
		constants.PermStandardAdminHasFull,
	), orgController.CreateOrganizationUser)
	/*============================================================================
	 |Accounting routes
	==============================================================================*/

	//accountingGroup := api.Group("/v1")
	//accountingGroup.Post("/self-credit", middleware.RequirePermissions(
	//	constants.PermEkdakDPMGFull,
	//	constants.PermCorporateDPMGFull,
	//), accountController.DPMGSelfCredit)

}
