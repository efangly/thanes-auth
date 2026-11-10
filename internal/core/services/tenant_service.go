package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
	"github.com/efangly/smtrack-authentication/pkg/logger"
	"github.com/google/uuid"
)

type tenantService struct {
	repo      ports.TenantRepository
	roles     ports.RoleRepository
	cache     ports.CachePort
	upload    ports.FileUploadPort
	messaging ports.MessagingPort
	audit     ports.AuditService
}

// NewTenantService creates a new tenant service
func NewTenantService(
	repo ports.TenantRepository,
	roles ports.RoleRepository,
	cache ports.CachePort,
	upload ports.FileUploadPort,
	messaging ports.MessagingPort,
	audit ports.AuditService,
) ports.TenantService {
	return &tenantService{
		repo:      repo,
		roles:     roles,
		cache:     cache,
		upload:    upload,
		messaging: messaging,
		audit:     audit,
	}
}

func (s *tenantService) Create(ctx context.Context, tenant *domain.Tenant, file *domain.File, caller *domain.Actor) (*domain.Tenant, error) {
	if tenant.Kind == "" {
		tenant.Kind = domain.TenantKindHospital
	} else if !tenant.Kind.IsValid() {
		return nil, fmt.Errorf("invalid tenant kind: %s", tenant.Kind)
	}
	if err := checkHiddenChange(caller, tenant.Hidden); err != nil {
		return nil, err
	}
	if tenant.ID == "" {
		tenant.ID = uuid.New().String()
	}

	if file != nil {
		picURL, err := s.upload.Upload(ctx, file, "tenant")
		if err != nil {
			return nil, fmt.Errorf("image upload failed: %w", err)
		}
		tenant.Pic = &picURL
	}

	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now

	result, err := s.repo.Create(ctx, tenant)
	if err != nil {
		discardImage(s.upload, "tenant", tenant.Pic)
		return nil, err
	}

	s.cache.Del(ctx, "tenant")
	s.audit.Record(ctx, domain.AuditEntityTenant, domain.AuditActionCreate, result.ID, caller, tenantSnapshot(result))
	return result, nil
}

func (s *tenantService) FindAll(ctx context.Context, caller *domain.Actor) ([]domain.Tenant, error) {
	filter, key, ok := buildTenantFilter(caller)
	if !ok {
		return []domain.Tenant{}, nil
	}

	var tenants []domain.Tenant
	if hit, err := s.cache.Get(ctx, key, &tenants); err != nil || !hit {
		var err error
		tenants, err = s.repo.FindAll(ctx, filter)
		if err != nil {
			return nil, err
		}
		if len(tenants) > 0 {
			s.cache.Set(ctx, key, tenants, listTTL)
		}
	}

	// The cache holds every department of a tenant; each caller gets only the
	// ones it may see.
	out := make([]domain.Tenant, len(tenants))
	for i, t := range tenants {
		t.Departments = visibleDepartments(caller, t.Departments)
		out[i] = t
	}
	return out, nil
}

func (s *tenantService) FindOne(ctx context.Context, id string, caller *domain.Actor) (*domain.Tenant, error) {
	if caller == nil {
		return nil, errors.New("unauthorized")
	}
	tenant, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	// Out of scope reads as not found, so a lookup by id never confirms a
	// tenant the caller's listing would hide.
	if tenant == nil || !canSeeTenant(caller, tenant) {
		return nil, errors.New("tenant not found")
	}
	tenant.Departments = visibleDepartments(caller, tenant.Departments)
	return tenant, nil
}

func (s *tenantService) Update(ctx context.Context, id string, patch domain.TenantPatch, file *domain.File, caller *domain.Actor) (*domain.Tenant, error) {
	existing, err := s.visibleTenant(ctx, id, caller)
	if err != nil {
		return nil, err
	}
	if patch.Kind != nil && *patch.Kind != existing.Kind {
		if err := s.checkKindChange(ctx, id, existing.Kind, *patch.Kind); err != nil {
			return nil, err
		}
	}
	if patch.Hidden != nil && *patch.Hidden != existing.Hidden {
		if err := checkHiddenChange(caller, *patch.Hidden); err != nil {
			return nil, err
		}
	}

	// See userService.Update: the old picture goes only after the update is saved.
	saved := false
	if file != nil {
		picURL, err := s.upload.Upload(ctx, file, "tenant")
		if err != nil {
			return nil, fmt.Errorf("image upload failed: %w", err)
		}
		patch.Pic = &picURL
		defer func() {
			if !saved {
				discardImage(s.upload, "tenant", &picURL)
			}
		}()
	}

	tenant, err := s.repo.Update(ctx, id, patch)
	if err != nil {
		return nil, err
	}
	saved = true
	if file != nil {
		discardImage(s.upload, "tenant", existing.Pic)
	}

	// Send notifications to other services
	if tenant != nil {
		notification := map[string]string{
			"id":   tenant.ID,
			"name": tenant.Name,
		}
		if err := s.messaging.SendToDevice("update-tenant", notification); err != nil {
			logger.Warn("Failed to send tenant update to device", "error", err, "tenantId", tenant.ID)
		}
		if err := s.messaging.SendToLegacy("update-tenant", notification); err != nil {
			logger.Warn("Failed to send tenant update to legacy", "error", err, "tenantId", tenant.ID)
		}
	}

	s.invalidate(ctx)
	s.audit.Record(ctx, domain.AuditEntityTenant, domain.AuditActionUpdate, id, caller, tenantPatchChanges(patch))
	return tenant, nil
}

func (s *tenantService) UpdateLabels(ctx context.Context, id string, labels domain.Labels, caller *domain.Actor) (*domain.Tenant, error) {
	if _, err := s.visibleTenant(ctx, id, caller); err != nil {
		return nil, err
	}
	// Its own tenant's admin may rename the labels; beyond that, only the
	// system-wide roles.
	if !canAdminTenant(caller, id) {
		return nil, errors.New("tenant not found")
	}
	if err := labels.Validate(); err != nil {
		return nil, err
	}

	if err := s.repo.SaveLabels(ctx, id, labels); err != nil {
		return nil, err
	}

	s.invalidate(ctx)
	s.audit.Record(ctx, domain.AuditEntityTenant, domain.AuditActionUpdate, id, caller, map[string]any{"labels": labels})
	return s.FindOne(ctx, id, caller)
}

// Remove soft-deletes a tenant, but only an empty one: deleting the people and
// departments of a whole organisation must be done deliberately, one by one.
func (s *tenantService) Remove(ctx context.Context, id string, caller *domain.Actor) (*domain.Tenant, error) {
	if _, err := s.visibleTenant(ctx, id, caller); err != nil {
		return nil, err
	}
	hasMembers, err := s.repo.HasMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	if hasMembers {
		return nil, errors.New("tenant is not empty")
	}

	tenant, err := s.repo.Delete(ctx, id, caller.ID)
	if err != nil {
		return nil, err
	}

	s.invalidate(ctx)
	s.audit.Record(ctx, domain.AuditEntityTenant, domain.AuditActionDelete, id, caller, tenantSnapshot(tenant))
	return tenant, nil
}

func (s *tenantService) Restore(ctx context.Context, id string, caller *domain.Actor) (*domain.Tenant, error) {
	if caller == nil {
		return nil, errors.New("unauthorized")
	}
	existing, err := s.repo.FindAnyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil || existing.DeletedAt == nil || !canSeeTenant(caller, existing) {
		return nil, errors.New("tenant not found")
	}

	tenant, err := s.repo.Restore(ctx, id)
	if err != nil {
		return nil, err
	}

	s.invalidate(ctx)
	s.audit.Record(ctx, domain.AuditEntityTenant, domain.AuditActionRestore, id, caller, tenantSnapshot(tenant))
	return tenant, nil
}

// visibleTenant loads a live tenant the caller may see, reporting anything
// else as not found.
func (s *tenantService) visibleTenant(ctx context.Context, id string, caller *domain.Actor) (*domain.Tenant, error) {
	if caller == nil {
		return nil, errors.New("unauthorized")
	}
	tenant, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if tenant == nil || !canSeeTenant(caller, tenant) {
		return nil, errors.New("tenant not found")
	}
	return tenant, nil
}

// invalidate clears every cache that embeds tenant data: department and user
// listings carry their tenant (ADR 0002).
func (s *tenantService) invalidate(ctx context.Context) {
	s.cache.Del(ctx, "tenant")
	s.cache.Del(ctx, "department")
	s.cache.Del(ctx, "user")
}

// checkHiddenChange allows only SUPER to make a tenant hidden or visible.
func checkHiddenChange(caller *domain.Actor, hidden bool) error {
	if hidden && (caller == nil || caller.Tier != domain.TierSuper) {
		return errors.New("only SUPER can create a hidden tenant")
	}
	return nil
}

// checkKindChange allows a tenant to change kind only when every role its users
// hold — soft-deleted users included, so a restore still works — exists in the
// new kind with the same tier. A role that would mean more, or nothing, there
// must be changed on those users first (ADR 0006).
func (s *tenantService) checkKindChange(ctx context.Context, id string, from, to domain.TenantKind) error {
	if !to.IsValid() {
		return fmt.Errorf("invalid tenant kind: %s", to)
	}
	held, err := s.roles.RolesHeldInTenant(ctx, id)
	if err != nil {
		return err
	}
	for _, role := range held {
		if role.IsPlatform() {
			continue
		}
		before, err := s.roles.FindRole(ctx, from, role)
		if err != nil {
			return err
		}
		after, err := s.roles.FindRole(ctx, to, role)
		if err != nil {
			return err
		}
		if after == nil || (before != nil && before.Tier != after.Tier) {
			return fmt.Errorf("users of this tenant hold role %s, which tenant kind %s does not have with the same tier", role, to)
		}
	}
	return nil
}

// buildTenantFilter is the tenant listing each tier may see, and its cache
// key. ok is false when the caller's scope is empty.
func buildTenantFilter(caller *domain.Actor) (filter ports.TenantFilter, key string, ok bool) {
	switch caller.Tier {
	case domain.TierSuper:
		return ports.TenantFilter{}, "tenant", true
	case domain.TierService:
		return ports.TenantFilter{ExcludeHidden: true}, "tenant:service", true
	case domain.TierAdmin:
		if caller.TenantID == "" {
			return filter, "", false
		}
		return ports.TenantFilter{ID: caller.TenantID, ExcludeHidden: true}, "tenant:" + caller.TenantID, true
	}
	if caller.TenantID == "" {
		return filter, "", false
	}
	return ports.TenantFilter{ID: caller.TenantID}, "tenant:" + caller.TenantID + ":member", true
}
