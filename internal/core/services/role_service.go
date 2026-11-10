package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
)

// roleService manages the role catalogue (ADR 0006). The catalogue is read
// straight from the repository, never cached: login, refresh and every user
// change authorize from it.
type roleService struct {
	repo  ports.RoleRepository
	audit ports.AuditService
}

// NewRoleService creates a new role catalogue service.
func NewRoleService(repo ports.RoleRepository, audit ports.AuditService) ports.RoleService {
	return &roleService{repo: repo, audit: audit}
}

// readableKind is the kind caller may read, given the kind it asked for. ok is
// false when it may read nothing. An empty result kind means every kind.
func readableKind(caller *domain.Actor, kind domain.TenantKind) (domain.TenantKind, bool) {
	if caller == nil {
		return "", false
	}
	switch caller.Tier {
	case domain.TierSuper, domain.TierService:
		return kind, true
	case domain.TierAdmin:
		// A tenant-scoped admin needs its own kind's roles to place users; any
		// other kind reads as empty.
		if caller.TenantKind == "" || (kind != "" && kind != caller.TenantKind) {
			return "", false
		}
		return caller.TenantKind, true
	}
	return "", false
}

func requireSuper(caller *domain.Actor) error {
	if caller == nil || caller.Tier != domain.TierSuper {
		return errors.New("only SUPER can change the role catalogue")
	}
	return nil
}

func checkKind(kind domain.TenantKind) error {
	if !kind.IsValid() {
		return fmt.Errorf("invalid tenant kind: %s", kind)
	}
	return nil
}

func catalogueID(kind domain.TenantKind, name string) string {
	return string(kind) + ":" + name
}

func (s *roleService) FindRoles(ctx context.Context, kind domain.TenantKind, caller *domain.Actor) ([]domain.RoleDefinition, error) {
	if kind != "" {
		if err := checkKind(kind); err != nil {
			return nil, err
		}
	}
	kind, ok := readableKind(caller, kind)
	if !ok {
		return []domain.RoleDefinition{}, nil
	}
	return s.repo.FindRoles(ctx, kind)
}

func (s *roleService) FindRole(ctx context.Context, kind domain.TenantKind, name domain.Role, caller *domain.Actor) (*domain.RoleDefinition, error) {
	readable, ok := readableKind(caller, kind)
	if !ok || (readable != "" && readable != kind) {
		return nil, errors.New("role not found")
	}
	role, err := s.repo.FindRole(ctx, kind, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, errors.New("role not found")
	}
	return role, nil
}

func (s *roleService) CreateRole(ctx context.Context, role *domain.RoleDefinition, caller *domain.Actor) (*domain.RoleDefinition, error) {
	if err := requireSuper(caller); err != nil {
		return nil, err
	}
	if err := checkKind(role.Kind); err != nil {
		return nil, err
	}
	if !role.Name.IsValidName() {
		return nil, fmt.Errorf("invalid role name: %s", role.Name)
	}
	if role.Name.IsPlatform() {
		return nil, fmt.Errorf("%s is a platform role", role.Name)
	}
	if !role.Tier.IsKindTier() {
		return nil, fmt.Errorf("invalid tier: %s", role.Tier)
	}
	existing, err := s.repo.FindRole(ctx, role.Kind, role.Name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("role already exists")
	}
	permissions, err := s.checkPermissions(ctx, role.Kind, role.Permissions)
	if err != nil {
		return nil, err
	}
	role.Permissions = permissions
	now := time.Now()
	role.CreatedAt, role.UpdatedAt = now, now

	created, err := s.repo.CreateRole(ctx, role)
	if err != nil {
		return nil, err
	}
	s.audit.Record(ctx, domain.AuditEntityRole, domain.AuditActionCreate, catalogueID(created.Kind, string(created.Name)), caller,
		map[string]any{"tier": created.Tier, "description": created.Description, "permissions": created.Permissions})
	return created, nil
}

func (s *roleService) UpdateRole(ctx context.Context, kind domain.TenantKind, name domain.Role, patch domain.RolePatch, caller *domain.Actor) (*domain.RoleDefinition, error) {
	if err := requireSuper(caller); err != nil {
		return nil, err
	}
	existing, err := s.repo.FindRole(ctx, kind, name)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.New("role not found")
	}
	changes := map[string]any{}
	if patch.Description != nil {
		changes["description"] = *patch.Description
	}
	if patch.Permissions != nil {
		permissions, err := s.checkPermissions(ctx, kind, *patch.Permissions)
		if err != nil {
			return nil, err
		}
		patch.Permissions = &permissions
		changes["permissions"] = permissions
	}

	updated, err := s.repo.UpdateRole(ctx, kind, name, patch)
	if err != nil {
		return nil, err
	}
	s.audit.Record(ctx, domain.AuditEntityRole, domain.AuditActionUpdate, catalogueID(kind, string(name)), caller, changes)
	return updated, nil
}

func (s *roleService) RemoveRole(ctx context.Context, kind domain.TenantKind, name domain.Role, caller *domain.Actor) error {
	if err := requireSuper(caller); err != nil {
		return err
	}
	existing, err := s.repo.FindRole(ctx, kind, name)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.New("role not found")
	}
	held, err := s.repo.RoleHeld(ctx, kind, name)
	if err != nil {
		return err
	}
	if held {
		return errors.New("role is still held by users")
	}
	if err := s.repo.DeleteRole(ctx, kind, name); err != nil {
		return err
	}
	s.audit.Record(ctx, domain.AuditEntityRole, domain.AuditActionDelete, catalogueID(kind, string(name)), caller,
		map[string]any{"tier": existing.Tier, "permissions": existing.Permissions})
	return nil
}

func (s *roleService) FindPermissions(ctx context.Context, kind domain.TenantKind, caller *domain.Actor) ([]domain.Permission, error) {
	if kind != "" {
		if err := checkKind(kind); err != nil {
			return nil, err
		}
	}
	kind, ok := readableKind(caller, kind)
	if !ok {
		return []domain.Permission{}, nil
	}
	return s.repo.FindPermissions(ctx, kind)
}

func (s *roleService) CreatePermission(ctx context.Context, permission *domain.Permission, caller *domain.Actor) (*domain.Permission, error) {
	if err := requireSuper(caller); err != nil {
		return nil, err
	}
	if err := checkKind(permission.Kind); err != nil {
		return nil, err
	}
	if !domain.IsValidPermissionKey(permission.Key) {
		return nil, fmt.Errorf("invalid permission key: %s", permission.Key)
	}
	existing, err := s.repo.FindPermission(ctx, permission.Kind, permission.Key)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("permission already exists")
	}
	now := time.Now()
	permission.CreatedAt, permission.UpdatedAt = now, now

	created, err := s.repo.CreatePermission(ctx, permission)
	if err != nil {
		return nil, err
	}
	s.audit.Record(ctx, domain.AuditEntityPermission, domain.AuditActionCreate, catalogueID(created.Kind, created.Key), caller,
		map[string]any{"description": created.Description})
	return created, nil
}

func (s *roleService) UpdatePermission(ctx context.Context, kind domain.TenantKind, key string, patch domain.PermissionPatch, caller *domain.Actor) (*domain.Permission, error) {
	if err := requireSuper(caller); err != nil {
		return nil, err
	}
	existing, err := s.repo.FindPermission(ctx, kind, key)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.New("permission not found")
	}
	updated, err := s.repo.UpdatePermission(ctx, kind, key, patch)
	if err != nil {
		return nil, err
	}
	changes := map[string]any{}
	if patch.Description != nil {
		changes["description"] = *patch.Description
	}
	s.audit.Record(ctx, domain.AuditEntityPermission, domain.AuditActionUpdate, catalogueID(kind, key), caller, changes)
	return updated, nil
}

func (s *roleService) RemovePermission(ctx context.Context, kind domain.TenantKind, key string, caller *domain.Actor) error {
	if err := requireSuper(caller); err != nil {
		return err
	}
	existing, err := s.repo.FindPermission(ctx, kind, key)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.New("permission not found")
	}
	granted, err := s.repo.PermissionGranted(ctx, kind, key)
	if err != nil {
		return err
	}
	if granted {
		return errors.New("permission is still granted by roles")
	}
	if err := s.repo.DeletePermission(ctx, kind, key); err != nil {
		return err
	}
	s.audit.Record(ctx, domain.AuditEntityPermission, domain.AuditActionDelete, catalogueID(kind, key), caller, nil)
	return nil
}

// checkPermissions requires every key to be registered for kind and returns
// them sorted without duplicates.
func (s *roleService) checkPermissions(ctx context.Context, kind domain.TenantKind, keys []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		permission, err := s.repo.FindPermission(ctx, kind, key)
		if err != nil {
			return nil, err
		}
		if permission == nil {
			return nil, fmt.Errorf("permission not found: %s", key)
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out, nil
}
