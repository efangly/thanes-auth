package http

import (
	"time"

	"github.com/efangly/smtrack-authentication/config"
	"github.com/efangly/smtrack-authentication/internal/adapters/driving/http/dto"
	"github.com/efangly/smtrack-authentication/internal/adapters/driving/http/handlers"
	"github.com/efangly/smtrack-authentication/internal/adapters/driving/http/middleware"
	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
	"github.com/efangly/smtrack-authentication/pkg/logger"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
)

type Router struct {
	app               *fiber.App
	cfg               *config.Config
	tokens            ports.TokenIssuer
	authHandler       *handlers.AuthHandler
	userHandler       *handlers.UserHandler
	tenantHandler     *handlers.TenantHandler
	departmentHandler *handlers.DepartmentHandler
	auditHandler      *handlers.AuditHandler
	roleHandler       *handlers.RoleHandler
	healthHandler     *handlers.HealthHandler
	imageHandler      *handlers.ImageHandler
}

func NewRouter(
	app *fiber.App,
	cfg *config.Config,
	tokens ports.TokenIssuer,
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler,
	tenantHandler *handlers.TenantHandler,
	departmentHandler *handlers.DepartmentHandler,
	auditHandler *handlers.AuditHandler,
	roleHandler *handlers.RoleHandler,
	healthHandler *handlers.HealthHandler,
	imageHandler *handlers.ImageHandler,
) *Router {
	return &Router{
		app:               app,
		cfg:               cfg,
		tokens:            tokens,
		authHandler:       authHandler,
		userHandler:       userHandler,
		tenantHandler:     tenantHandler,
		departmentHandler: departmentHandler,
		auditHandler:      auditHandler,
		roleHandler:       roleHandler,
		healthHandler:     healthHandler,
		imageHandler:      imageHandler,
	}
}

func (r *Router) Setup() {
	auth := r.app.Group("/auth")

	// Behind KrakenD every connection comes from the gateway, so without this
	// the limiter below would put all clients into one shared bucket.
	proxies, err := middleware.ParseTrustedProxies(r.cfg.TrustedProxies)
	if err != nil {
		logger.Fatal("Invalid TRUSTED_PROXIES", "error", err)
	}

	// Public routes (no auth required). Rate limited per client IP so
	// credentials cannot be brute forced and accounts cannot be mass-created.
	publicLimiter := limiter.New(limiter.Config{
		Max:          10,
		Expiration:   time.Minute,
		KeyGenerator: proxies.ClientIP,
		LimitReached: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).
				JSON(dto.FailResponse("Too many requests, please try again later"))
		},
	})
	auth.Post("/register", publicLimiter, r.authHandler.Register)
	auth.Post("/login", publicLimiter, r.authHandler.Login)

	// Refresh token route (requires refresh JWT)
	auth.Post("/refresh", middleware.RefreshJWTAuth(r.tokens), r.authHandler.RefreshToken)

	// Reset password (requires JWT). The path parameter is a username, not an id.
	auth.Patch("/reset/:username", middleware.JWTAuth(r.tokens), r.authHandler.ResetPassword)

	// Logout (requires the access token; the body carries the refresh token to revoke).
	auth.Post("/logout", middleware.JWTAuth(r.tokens), r.authHandler.Logout)

	// Health check
	auth.Get("/health", r.healthHandler.Check)

	// Stored pictures (public, like the image URLs they replace)
	auth.Get("/image/:path/:name", r.imageHandler.Get)

	// JWT-protected middleware
	jwtAuth := middleware.JWTAuth(r.tokens)

	// Guards by tier (ADR 0006): which roles hold a tier comes from the catalogue.
	adminTier := middleware.TiersGuard(domain.TierSuper, domain.TierService, domain.TierAdmin)
	systemWide := middleware.TiersGuard(domain.TierSuper, domain.TierService)
	superOnly := middleware.TiersGuard(domain.TierSuper)

	// User routes
	userGroup := auth.Group("/user", jwtAuth)
	userGroup.Post("/",
		adminTier,
		r.userHandler.Create,
	)
	userGroup.Get("/",
		adminTier,
		r.userHandler.FindAll,
	)
	// FindOne and Update additionally enforce ownership inside the handler:
	// a non-admin caller may only touch its own record.
	userGroup.Get("/:id", r.userHandler.FindOne)
	userGroup.Put("/:id", r.userHandler.Update)
	userGroup.Delete("/:id",
		adminTier,
		r.userHandler.Remove,
	)
	userGroup.Post("/:id/restore",
		adminTier,
		r.userHandler.Restore,
	)

	// Access review: who holds which role where, and when they last signed in.
	auth.Get("/report/access", jwtAuth,
		adminTier,
		r.userHandler.AccessReport,
	)

	// Tenant routes
	tenantGroup := auth.Group("/tenant", jwtAuth)
	tenantGroup.Post("/",
		systemWide,
		r.tenantHandler.Create,
	)
	tenantGroup.Get("/", r.tenantHandler.FindAll)
	tenantGroup.Get("/:id", r.tenantHandler.FindOne)
	tenantGroup.Put("/:id",
		systemWide,
		r.tenantHandler.Update,
	)
	// A tenant's own admin may rename its labels; the service confirms the
	// tenant is the caller's.
	tenantGroup.Put("/:id/labels",
		adminTier,
		r.tenantHandler.UpdateLabels,
	)
	tenantGroup.Delete("/:id",
		superOnly,
		r.tenantHandler.Remove,
	)
	tenantGroup.Post("/:id/restore",
		superOnly,
		r.tenantHandler.Restore,
	)

	// Department routes
	departmentGroup := auth.Group("/department", jwtAuth)
	departmentGroup.Post("/",
		systemWide,
		r.departmentHandler.Create,
	)
	departmentGroup.Get("/", r.departmentHandler.FindAll)
	departmentGroup.Get("/:id", r.departmentHandler.FindOne)
	// Every mutating route carries a guard: without one any authenticated
	// caller — including a self-registered GUEST — could rename or delete any
	// department.
	departmentGroup.Put("/:id",
		systemWide,
		r.departmentHandler.Update,
	)
	departmentGroup.Delete("/:id",
		systemWide,
		r.departmentHandler.Remove,
	)
	departmentGroup.Post("/:id/restore",
		systemWide,
		r.departmentHandler.Restore,
	)

	// Role catalogue. Reading is scoped in the service (a tenant-scoped admin
	// sees its own kind); only SUPER changes it.
	roleGroup := auth.Group("/role", jwtAuth)
	roleGroup.Get("/", adminTier, r.roleHandler.FindRoles)
	roleGroup.Post("/", superOnly, r.roleHandler.CreateRole)
	roleGroup.Get("/:kind/:name", adminTier, r.roleHandler.FindRole)
	roleGroup.Put("/:kind/:name", superOnly, r.roleHandler.UpdateRole)
	roleGroup.Delete("/:kind/:name", superOnly, r.roleHandler.RemoveRole)

	permissionGroup := auth.Group("/permission", jwtAuth)
	permissionGroup.Get("/", adminTier, r.roleHandler.FindPermissions)
	permissionGroup.Post("/", superOnly, r.roleHandler.CreatePermission)
	permissionGroup.Put("/:kind/:key", superOnly, r.roleHandler.UpdatePermission)
	permissionGroup.Delete("/:kind/:key", superOnly, r.roleHandler.RemovePermission)

	// Audit log routes (read-only). Logs are not tenant-scoped, so only the
	// system-wide roles may read them.
	auditGroup := auth.Group("/audit", jwtAuth)
	auditGroup.Get("/",
		systemWide,
		r.auditHandler.FindAll,
	)
}
