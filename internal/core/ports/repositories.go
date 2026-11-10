package ports

import (
	"context"
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
)

// The *Filter types narrow a listing. Zero-value fields are not applied.
// Every listing and lookup excludes soft-deleted records unless it is named
// as including them.

// UserFilter narrows a user listing.
type UserFilter struct {
	TenantID string
	// ExcludeHiddenTenants drops users of hidden tenants.
	ExcludeHiddenTenants bool
	ExcludeRoles         []domain.Role
}

// DepartmentFilter narrows a department listing.
type DepartmentFilter struct {
	TenantID string
	// IDs, when LimitToIDs is set, keeps only these departments; an empty
	// list then matches nothing.
	IDs        []string
	LimitToIDs bool
	// ExcludeHiddenTenants drops departments of hidden tenants.
	ExcludeHiddenTenants bool
}

// TenantFilter narrows a tenant listing.
type TenantFilter struct {
	ID string
	// ExcludeHidden drops hidden tenants.
	ExcludeHidden bool
}

// Repositories set the updated-at timestamp themselves on every Update.
// Delete is a soft delete; Restore undoes it. FindAnyByID also finds
// soft-deleted records and is only for authorizing a restore.

type UserRepository interface {
	// Create stores the user and links DepartmentIDs.
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
	FindAll(ctx context.Context, filter UserFilter) ([]domain.User, error)
	// FindByID and FindByUsername load the tenant and departments.
	FindByID(ctx context.Context, id string) (*domain.User, error)
	FindByUsername(ctx context.Context, username string) (*domain.User, error)
	FindAnyByID(ctx context.Context, id string) (*domain.User, error)
	// UsernameTaken includes soft-deleted users: a username stays reserved.
	UsernameTaken(ctx context.Context, username string) (bool, error)
	Update(ctx context.Context, id string, patch domain.UserPatch) (*domain.User, error)
	Delete(ctx context.Context, id string, deletedBy string) (*domain.User, error)
	Restore(ctx context.Context, id string) (*domain.User, error)
	// RecordLogin stamps last_login_at without touching updated_at.
	RecordLogin(ctx context.Context, id string, at time.Time) error
}

type DepartmentRepository interface {
	Create(ctx context.Context, department *domain.Department) (*domain.Department, error)
	FindAll(ctx context.Context, filter DepartmentFilter) ([]domain.Department, error)
	FindByID(ctx context.Context, id string) (*domain.Department, error)
	FindByIDs(ctx context.Context, ids []string) ([]domain.Department, error)
	FindAnyByID(ctx context.Context, id string) (*domain.Department, error)
	// NameTaken reports whether a live department of the tenant already has
	// the name, ignoring exceptID.
	NameTaken(ctx context.Context, tenantID, name, exceptID string) (bool, error)
	Update(ctx context.Context, id string, patch domain.DepartmentPatch) (*domain.Department, error)
	Delete(ctx context.Context, id string, deletedBy string) (*domain.Department, error)
	Restore(ctx context.Context, id string) (*domain.Department, error)
}

type TenantRepository interface {
	Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	// FindAll and FindByID load the label profile and live departments.
	FindAll(ctx context.Context, filter TenantFilter) ([]domain.Tenant, error)
	FindByID(ctx context.Context, id string) (*domain.Tenant, error)
	FindAnyByID(ctx context.Context, id string) (*domain.Tenant, error)
	// HasMembers reports whether the tenant still has live users or departments.
	HasMembers(ctx context.Context, id string) (bool, error)
	Update(ctx context.Context, id string, patch domain.TenantPatch) (*domain.Tenant, error)
	// SaveLabels replaces the tenant's label profile.
	SaveLabels(ctx context.Context, id string, labels domain.Labels) error
	Delete(ctx context.Context, id string, deletedBy string) (*domain.Tenant, error)
	Restore(ctx context.Context, id string) (*domain.Tenant, error)
}

// RoleRepository stores the role catalogue (ADR 0006). Finds return nil, nil
// when nothing matches. The catalogue has no soft delete: a role or permission
// can only be removed once nothing uses it.
type RoleRepository interface {
	// FindRoles lists the roles of kind, or of every kind when kind is empty,
	// with their permissions.
	FindRoles(ctx context.Context, kind domain.TenantKind) ([]domain.RoleDefinition, error)
	FindRole(ctx context.Context, kind domain.TenantKind, name domain.Role) (*domain.RoleDefinition, error)
	// CreateRole stores the role and the permissions it grants.
	CreateRole(ctx context.Context, role *domain.RoleDefinition) (*domain.RoleDefinition, error)
	UpdateRole(ctx context.Context, kind domain.TenantKind, name domain.Role, patch domain.RolePatch) (*domain.RoleDefinition, error)
	DeleteRole(ctx context.Context, kind domain.TenantKind, name domain.Role) error
	// RoleHeld reports whether any user of a tenant of kind holds the role,
	// counting soft-deleted users and tenants: a restore must find it again.
	RoleHeld(ctx context.Context, kind domain.TenantKind, name domain.Role) (bool, error)
	// RolesHeldInTenant lists the distinct roles the tenant's users hold,
	// counting soft-deleted users.
	RolesHeldInTenant(ctx context.Context, tenantID string) ([]domain.Role, error)

	// FindPermissions lists the permissions of kind, or of every kind when
	// kind is empty.
	FindPermissions(ctx context.Context, kind domain.TenantKind) ([]domain.Permission, error)
	FindPermission(ctx context.Context, kind domain.TenantKind, key string) (*domain.Permission, error)
	CreatePermission(ctx context.Context, permission *domain.Permission) (*domain.Permission, error)
	UpdatePermission(ctx context.Context, kind domain.TenantKind, key string, patch domain.PermissionPatch) (*domain.Permission, error)
	DeletePermission(ctx context.Context, kind domain.TenantKind, key string) error
	// PermissionGranted reports whether any role still grants the permission.
	PermissionGranted(ctx context.Context, kind domain.TenantKind, key string) (bool, error)
}

// AuditFilter narrows an audit log query. Zero-value fields are not applied.
type AuditFilter struct {
	Entity   string
	Action   string
	EntityID string
	ActorID  string
	Limit    int
	Offset   int
}

type AuditRepository interface {
	Create(ctx context.Context, log *domain.AuditLog) (*domain.AuditLog, error)
	FindAll(ctx context.Context, filter AuditFilter) ([]domain.AuditLog, error)
}
