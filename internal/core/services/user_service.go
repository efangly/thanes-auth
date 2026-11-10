package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
	"github.com/google/uuid"
)

type userService struct {
	repo           ports.UserRepository
	tenantRepo     ports.TenantRepository
	departmentRepo ports.DepartmentRepository
	roles          ports.RoleRepository
	cache          ports.CachePort
	upload         ports.FileUploadPort
	hasher         ports.PasswordHasher
	audit          ports.AuditService
}

// NewUserService creates a new user service
func NewUserService(
	repo ports.UserRepository,
	tenantRepo ports.TenantRepository,
	departmentRepo ports.DepartmentRepository,
	roles ports.RoleRepository,
	cache ports.CachePort,
	upload ports.FileUploadPort,
	hasher ports.PasswordHasher,
	audit ports.AuditService,
) ports.UserService {
	return &userService{
		repo:           repo,
		tenantRepo:     tenantRepo,
		departmentRepo: departmentRepo,
		roles:          roles,
		cache:          cache,
		upload:         upload,
		hasher:         hasher,
		audit:          audit,
	}
}

func (s *userService) Create(ctx context.Context, user *domain.User, caller *domain.Actor) (*domain.User, error) {
	// An unset role falls back to the least-privileged one.
	if user.Role == "" {
		user.Role = domain.RoleGuest
	}
	// Public registration (no caller) can only ever produce a GUEST without
	// departments; an authenticated caller is held to its role ceiling.
	if caller == nil {
		if user.Role != domain.RoleGuest {
			return nil, fmt.Errorf("you cannot assign role %s", user.Role)
		}
		if len(user.DepartmentIDs) > 0 {
			return nil, errors.New("you cannot assign departments")
		}
	} else if !caller.IsAdminTier() {
		// Below the admin tier no role is within the ceiling.
		return nil, fmt.Errorf("you cannot assign role %s", user.Role)
	}
	tenant, err := s.checkTenantInScope(ctx, caller, user.TenantID)
	if err != nil {
		return nil, err
	}
	// The role must exist for the tenant's kind, and its tier decides the ceiling.
	if err := s.checkAssignable(ctx, caller, tenant.Kind, user.Role); err != nil {
		return nil, err
	}
	if err := s.checkDepartments(ctx, user.TenantID, user.DepartmentIDs); err != nil {
		return nil, err
	}

	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	user.Username = strings.ToLower(user.Username)
	if taken, err := s.repo.UsernameTaken(ctx, user.Username); err != nil {
		return nil, err
	} else if taken {
		return nil, errors.New("username already exists")
	}

	// Every path into Create carries a plain-text password — both the public
	// register flow (authService.Register passes it straight through) and the
	// authenticated POST /auth/user — so it must be hashed here, mirroring the
	// password branch in Update.
	hashedPassword, err := s.hasher.Hash(user.Password)
	if err != nil {
		return nil, err
	}
	user.Password = hashedPassword

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	result, err := s.repo.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	// Clear cache
	s.cache.Del(ctx, "user")
	s.audit.Record(ctx, domain.AuditEntityUser, domain.AuditActionCreate, result.ID, caller, userSnapshot(result))
	return result, nil
}

func (s *userService) FindAll(ctx context.Context, caller *domain.Actor) ([]domain.User, error) {
	filter, key, ok := buildUserFilter(caller)
	if !ok {
		return []domain.User{}, nil
	}

	var cached []domain.User
	if hit, err := s.cache.Get(ctx, key, &cached); err == nil && hit {
		return cached, nil
	}

	users, err := s.repo.FindAll(ctx, filter)
	if err != nil {
		return nil, err
	}

	if len(users) > 0 {
		s.cache.Set(ctx, key, domain.UsersWithoutSecrets(users), listTTL)
	}

	return users, nil
}

func (s *userService) RecordLogin(ctx context.Context, id string) error {
	if err := s.repo.RecordLogin(ctx, id, time.Now()); err != nil {
		return err
	}
	// Listings embed lastLoginAt; let them refresh rather than serve a stale value for long.
	s.cache.Del(ctx, fmt.Sprintf("user:%s", id))
	return nil
}

func (s *userService) AccessReport(ctx context.Context, caller *domain.Actor) ([]ports.AccessEntry, error) {
	if caller == nil || !caller.IsAdminTier() {
		return nil, errors.New("unauthorized")
	}
	filter, _, ok := buildUserFilter(caller)
	if !ok {
		return []ports.AccessEntry{}, nil
	}
	// Straight from the database: a review must not see a cached copy.
	users, err := s.repo.FindAll(ctx, filter)
	if err != nil {
		return nil, err
	}
	// A role the catalogue no longer knows is reported with no tier, so the
	// review shows it rather than hiding the user.
	type roleKey struct {
		kind domain.TenantKind
		role domain.Role
	}
	resolved := map[roleKey]*domain.RoleDefinition{}
	entries := make([]ports.AccessEntry, len(users))
	for i, u := range users {
		kind, err := tenantKindOf(ctx, s.tenantRepo, &u)
		if err != nil {
			return nil, err
		}
		key := roleKey{kind, u.Role}
		def, seen := resolved[key]
		if !seen {
			if def, err = resolveRole(ctx, s.roles, kind, u.Role); err != nil {
				return nil, err
			}
			resolved[key] = def
		}
		entry := ports.AccessEntry{User: u.WithoutSecrets(), Permissions: []string{}}
		if def != nil {
			entry.Tier, entry.Permissions = def.Tier, def.Permissions
		}
		entries[i] = entry
	}
	s.audit.Record(ctx, domain.AuditEntityUser, domain.AuditActionAccessReport, caller.ID, caller,
		map[string]any{"users": len(users)})
	return entries, nil
}

func (s *userService) FindOne(ctx context.Context, id string, caller *domain.Actor) (*domain.User, error) {
	if caller == nil {
		return nil, errors.New("unauthorized")
	}
	if caller.ID != id && !caller.IsAdminTier() {
		return nil, errors.New("user not found")
	}

	user, err := s.findOneCached(ctx, id)
	if err != nil {
		return nil, err
	}
	if caller.ID != id && !canAdminTenant(caller, user.TenantID) {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (s *userService) findOneCached(ctx context.Context, id string) (*domain.User, error) {
	cacheKey := fmt.Sprintf("user:%s", id)

	var cached domain.User
	if hit, err := s.cache.Get(ctx, cacheKey, &cached); err == nil && hit {
		return &cached, nil
	}

	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	s.cache.Set(ctx, cacheKey, user.WithoutSecrets(), itemTTL)

	return user, nil
}

func (s *userService) FindByID(ctx context.Context, id string) (*domain.User, error) {
	return s.repo.FindByID(ctx, id)
}

func (s *userService) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	// Uncached on purpose: cached users have their password hash stripped, and
	// the auth flows need it.
	user, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *userService) UsernameTaken(ctx context.Context, username string) (bool, error) {
	return s.repo.UsernameTaken(ctx, username)
}

func (s *userService) Update(ctx context.Context, id string, patch domain.UserPatch, file *domain.File, caller *domain.Actor) (*domain.User, error) {
	target, err := s.authorizeChange(ctx, id, caller)
	if err != nil {
		return nil, err
	}

	tenantID := target.TenantID
	kind, err := tenantKindOf(ctx, s.tenantRepo, target)
	if err != nil {
		return nil, err
	}
	newKind := kind
	if patch.TenantID != nil && *patch.TenantID != target.TenantID {
		tenant, err := s.checkTenantInScope(ctx, caller, *patch.TenantID)
		if err != nil {
			return nil, err
		}
		// Department links belong to one tenant, so moving a user means saying
		// which departments it has in the new one.
		if patch.DepartmentIDs == nil {
			return nil, errors.New("departmentIds is required when changing tenant")
		}
		// Roles belong to one tenant kind in the same way.
		if tenant.Kind != kind && patch.Role == nil && !target.Role.IsPlatform() {
			return nil, errors.New("role is required when changing to a tenant of another kind")
		}
		tenantID = *patch.TenantID
		newKind = tenant.Kind
	}
	if patch.DepartmentIDs != nil {
		if err := s.checkDepartments(ctx, tenantID, *patch.DepartmentIDs); err != nil {
			return nil, err
		}
	}

	if patch.Username != nil && *patch.Username != target.Username {
		if taken, err := s.repo.UsernameTaken(ctx, *patch.Username); err != nil {
			return nil, err
		} else if taken {
			return nil, errors.New("username already exists")
		}
	}

	// The same role name can mean another tier in another kind, so a move
	// re-checks it even when the name stays.
	if patch.Role != nil && (*patch.Role != target.Role || newKind != kind) {
		if caller.ID == id && *patch.Role != target.Role {
			return nil, errors.New("you cannot change your own role")
		}
		if err := s.checkAssignable(ctx, caller, newKind, *patch.Role); err != nil {
			return nil, err
		}
	}

	// A new picture is uploaded first, but the old one is removed only once the
	// update is saved; if anything fails before then, the new one is removed
	// instead, so the record keeps pointing at a file that exists.
	saved := false
	if file != nil {
		picURL, err := s.upload.Upload(ctx, file, "user")
		if err != nil {
			return nil, fmt.Errorf("image upload failed: %w", err)
		}
		patch.Pic = &picURL
		defer func() {
			if !saved {
				discardImage(s.upload, "user", &picURL)
			}
		}()
	}

	// A password must never reach the database in plain text. This is the single
	// place that hashes on update, so callers pass the plain value.
	if patch.Password != nil {
		if *patch.Password == "" {
			return nil, errors.New("invalid password")
		}
		hashed, err := s.hasher.Hash(*patch.Password)
		if err != nil {
			return nil, err
		}
		patch.Password = &hashed
	}

	updatedUser, err := s.repo.Update(ctx, id, patch)
	if err != nil {
		return nil, err
	}
	saved = true
	if file != nil {
		discardImage(s.upload, "user", target.Pic)
	}

	s.invalidate(ctx, id, target.Username)
	if updatedUser != nil && updatedUser.Username != "" {
		s.cache.Del(ctx, fmt.Sprintf("user:%s", updatedUser.Username))
	}

	s.audit.Record(ctx, domain.AuditEntityUser, domain.AuditActionUpdate, id, caller, userPatchChanges(patch))
	return updatedUser, nil
}

// Remove soft-deletes a user. Its image is kept so a restore brings the whole
// record back; it is deleted when the user is purged.
func (s *userService) Remove(ctx context.Context, id string, caller *domain.Actor) (*domain.User, error) {
	if _, err := s.authorizeChange(ctx, id, caller); err != nil {
		return nil, err
	}

	user, err := s.repo.Delete(ctx, id, caller.ID)
	if err != nil {
		return nil, err
	}

	s.invalidate(ctx, id, user.Username)
	s.audit.Record(ctx, domain.AuditEntityUser, domain.AuditActionDelete, id, caller, userSnapshot(user))
	return user, nil
}

// Restore brings a soft-deleted user back under the same scope and role
// ceiling that let the caller delete it.
func (s *userService) Restore(ctx context.Context, id string, caller *domain.Actor) (*domain.User, error) {
	if caller == nil {
		return nil, errors.New("unauthorized")
	}
	target, err := s.repo.FindAnyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if target == nil || target.DeletedAt == nil || !canAdminTenant(caller, target.TenantID) {
		return nil, errors.New("user not found")
	}
	tenant, err := s.tenantRepo.FindByID(ctx, target.TenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, errors.New("tenant not found")
	}
	tier, err := targetTier(ctx, s.roles, tenant.Kind, target.Role)
	if err != nil {
		return nil, err
	}
	if !caller.CanAssign(tier) {
		return nil, errors.New("you do not have permission to modify this user")
	}

	user, err := s.repo.Restore(ctx, id)
	if err != nil {
		return nil, err
	}

	s.invalidate(ctx, id, user.Username)
	s.audit.Record(ctx, domain.AuditEntityUser, domain.AuditActionRestore, id, caller, userSnapshot(user))
	return user, nil
}

func (s *userService) invalidate(ctx context.Context, id, username string) {
	s.cache.Del(ctx, "user")
	s.cache.Del(ctx, fmt.Sprintf("user:%s", id))
	if username != "" {
		s.cache.Del(ctx, fmt.Sprintf("user:%s", username))
	}
}

// authorizeChange loads the user about to be updated or removed and checks
// that caller may act on it: anyone may act on their own record, but acting on
// somebody else's requires that user to be in the caller's tenant scope and
// within its role ceiling. A user outside the scope is reported as not found so
// its existence is not revealed.
// It reads the repository directly so the decision is never made on a stale
// cached role.
func (s *userService) authorizeChange(ctx context.Context, id string, caller *domain.Actor) (*domain.User, error) {
	if caller == nil {
		return nil, errors.New("unauthorized")
	}
	target, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, errors.New("user not found")
	}
	if caller.ID != id {
		if !canAdminTenant(caller, target.TenantID) {
			return nil, errors.New("user not found")
		}
		kind, err := tenantKindOf(ctx, s.tenantRepo, target)
		if err != nil {
			return nil, err
		}
		tier, err := targetTier(ctx, s.roles, kind, target.Role)
		if err != nil {
			return nil, err
		}
		if !caller.CanAssign(tier) {
			return nil, errors.New("you do not have permission to modify this user")
		}
	}
	return target, nil
}

// checkAssignable requires role to exist for kind and to be within caller's
// role ceiling. A nil caller is public registration, which Create has already
// confined to GUEST.
func (s *userService) checkAssignable(ctx context.Context, caller *domain.Actor, kind domain.TenantKind, role domain.Role) error {
	def, err := resolveRole(ctx, s.roles, kind, role)
	if err != nil {
		return err
	}
	if def == nil {
		return fmt.Errorf("invalid role: %s", role)
	}
	if caller != nil && !caller.CanAssign(def.Tier) {
		return fmt.Errorf("you cannot assign role %s", role)
	}
	return nil
}

// checkTenantInScope rejects placing a user into a tenant that does not exist
// or is outside the caller's scope. A nil caller is public registration, which
// may not join a hidden tenant. A tenant that cannot be used reads as not found.
func (s *userService) checkTenantInScope(ctx context.Context, caller *domain.Actor, tenantID string) (*domain.Tenant, error) {
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, errors.New("tenant not found")
	}
	if caller == nil {
		if tenant.Hidden {
			return nil, errors.New("tenant not found")
		}
		return tenant, nil
	}
	if !canAdminTenant(caller, tenant.ID) {
		return nil, errors.New("tenant not found")
	}
	return tenant, nil
}

// checkDepartments requires every department to exist and belong to tenantID.
func (s *userService) checkDepartments(ctx context.Context, tenantID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	found, err := s.departmentRepo.FindByIDs(ctx, ids)
	if err != nil {
		return err
	}
	byID := make(map[string]domain.Department, len(found))
	for _, d := range found {
		byID[d.ID] = d
	}
	for _, id := range ids {
		if d, ok := byID[id]; !ok || d.TenantID != tenantID {
			return errors.New("department not found")
		}
	}
	return nil
}

// buildUserFilter is the user listing each tier may see, and its cache key. ok
// is false when the caller's scope is empty (a tenant-scoped tier whose token
// names no tenant), which must list nothing rather than everything.
func buildUserFilter(caller *domain.Actor) (filter ports.UserFilter, key string, ok bool) {
	switch caller.Tier {
	case domain.TierSuper:
		return ports.UserFilter{}, "user", true
	case domain.TierService:
		return ports.UserFilter{ExcludeHiddenTenants: true}, "user:service", true
	case domain.TierAdmin:
		if caller.TenantID == "" {
			return filter, "", false
		}
		return ports.UserFilter{
			TenantID:             caller.TenantID,
			ExcludeHiddenTenants: true,
			ExcludeRoles:         []domain.Role{domain.RoleService},
		}, "user:tenant:" + caller.TenantID, true
	}
	if caller.TenantID == "" {
		return filter, "", false
	}
	return ports.UserFilter{TenantID: caller.TenantID}, "user:tenant:" + caller.TenantID + ":member", true
}
