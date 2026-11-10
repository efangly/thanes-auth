package services

import (
	"context"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
)

// resolveRole is what role name means for a tenant of kind: a platform role
// resolves without the catalogue, any other through it. It returns nil, nil
// when kind has no such role. It reads the repository directly, never a
// cache, because authorization depends on it (ADR 0006).
func resolveRole(ctx context.Context, repo ports.RoleRepository, kind domain.TenantKind, name domain.Role) (*domain.RoleDefinition, error) {
	if def := domain.PlatformRole(name); def != nil {
		return def, nil
	}
	return repo.FindRole(ctx, kind, name)
}

// targetTier is the tier to hold a caller to before it acts on an existing
// user who holds role in a tenant of kind. A role the catalogue no longer
// knows counts as ADMIN, so only SUPER and SERVICE can repair such a user.
func targetTier(ctx context.Context, repo ports.RoleRepository, kind domain.TenantKind, role domain.Role) (domain.Tier, error) {
	def, err := resolveRole(ctx, repo, kind, role)
	if err != nil {
		return "", err
	}
	if def == nil {
		return domain.TierAdmin, nil
	}
	return def.Tier, nil
}

// tenantKindOf is the kind of the user's tenant, from the loaded tenant when
// the read filled it.
func tenantKindOf(ctx context.Context, tenants ports.TenantRepository, user *domain.User) (domain.TenantKind, error) {
	if user.Tenant != nil {
		return user.Tenant.Kind, nil
	}
	tenant, err := tenants.FindAnyByID(ctx, user.TenantID)
	if err != nil {
		return "", err
	}
	if tenant == nil {
		return "", nil
	}
	return tenant.Kind, nil
}
