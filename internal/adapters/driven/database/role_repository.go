package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
	"gorm.io/gorm"
)

type roleRepository struct {
	db *gorm.DB
}

// NewRoleRepository creates the role catalogue repository adapter.
func NewRoleRepository(db *gorm.DB) ports.RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) FindRoles(ctx context.Context, kind domain.TenantKind) ([]domain.RoleDefinition, error) {
	var models []roleModel
	query := r.db.WithContext(ctx).Order("kind ASC, name ASC")
	if kind != "" {
		query = query.Where("kind = ?", string(kind))
	}
	if err := query.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	granted, err := r.grants(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := make([]domain.RoleDefinition, len(models))
	for i, m := range models {
		out[i] = m.toDomain(granted[m.Kind+"\x00"+m.Name])
	}
	return out, nil
}

// grants maps kind+"\x00"+role to the permission keys it grants, sorted.
func (r *roleRepository) grants(ctx context.Context, kind domain.TenantKind) (map[string][]string, error) {
	var rows []rolePermissionModel
	query := r.db.WithContext(ctx).Order("permission_key ASC")
	if kind != "" {
		query = query.Where("kind = ?", string(kind))
	}
	if err := query.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	out := map[string][]string{}
	for _, row := range rows {
		key := row.Kind + "\x00" + row.RoleName
		out[key] = append(out[key], row.PermissionKey)
	}
	return out, nil
}

func (r *roleRepository) FindRole(ctx context.Context, kind domain.TenantKind, name domain.Role) (*domain.RoleDefinition, error) {
	var model roleModel
	err := r.db.WithContext(ctx).Where("kind = ? AND name = ?", string(kind), string(name)).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	var keys []string
	if err := r.db.WithContext(ctx).Model(&rolePermissionModel{}).
		Where("kind = ? AND role_name = ?", string(kind), string(name)).
		Order("permission_key ASC").Pluck("permission_key", &keys).Error; err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	role := model.toDomain(keys)
	return &role, nil
}

func (r *roleRepository) CreateRole(ctx context.Context, role *domain.RoleDefinition) (*domain.RoleDefinition, error) {
	model := roleModel{
		Kind: string(role.Kind), Name: string(role.Name), Tier: string(role.Tier),
		Description: role.Description, CreatedAt: role.CreatedAt, UpdatedAt: role.UpdatedAt,
	}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&model).Error; err != nil {
			return err
		}
		return grantPermissions(tx, model.Kind, model.Name, role.Permissions)
	})
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return r.FindRole(ctx, role.Kind, role.Name)
}

// UpdateRole never touches the tier: it cannot change once a role exists.
func (r *roleRepository) UpdateRole(ctx context.Context, kind domain.TenantKind, name domain.Role, patch domain.RolePatch) (*domain.RoleDefinition, error) {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		columns := map[string]any{"updated_at": time.Now()}
		if patch.Description != nil {
			columns["description"] = *patch.Description
		}
		if err := tx.Model(&roleModel{}).Where("kind = ? AND name = ?", string(kind), string(name)).Updates(columns).Error; err != nil {
			return err
		}
		if patch.Permissions == nil {
			return nil
		}
		if err := tx.Where("kind = ? AND role_name = ?", string(kind), string(name)).Delete(&rolePermissionModel{}).Error; err != nil {
			return err
		}
		return grantPermissions(tx, string(kind), string(name), *patch.Permissions)
	})
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return r.FindRole(ctx, kind, name)
}

func grantPermissions(tx *gorm.DB, kind, role string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	rows := make([]rolePermissionModel, len(keys))
	for i, key := range keys {
		rows[i] = rolePermissionModel{Kind: kind, RoleName: role, PermissionKey: key}
	}
	return tx.Create(&rows).Error
}

func (r *roleRepository) DeleteRole(ctx context.Context, kind domain.TenantKind, name domain.Role) error {
	// role_permissions rows go with it (ON DELETE CASCADE).
	if err := r.db.WithContext(ctx).Where("kind = ? AND name = ?", string(kind), string(name)).Delete(&roleModel{}).Error; err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	return nil
}

func (r *roleRepository) RoleHeld(ctx context.Context, kind domain.TenantKind, name domain.Role) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Unscoped().Model(&userModel{}).
		Where("users.role = ?", string(name)).
		Where("users.tenant_id IN (?)", r.db.Unscoped().Model(&tenantModel{}).Select("id").Where("kind = ?", string(kind))).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("database error: %w", err)
	}
	return count > 0, nil
}

func (r *roleRepository) RolesHeldInTenant(ctx context.Context, tenantID string) ([]domain.Role, error) {
	var names []string
	err := r.db.WithContext(ctx).Unscoped().Model(&userModel{}).
		Where("tenant_id = ?", tenantID).Distinct().Order("role ASC").Pluck("role", &names).Error
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	out := make([]domain.Role, len(names))
	for i, n := range names {
		out[i] = domain.Role(n)
	}
	return out, nil
}

func (r *roleRepository) FindPermissions(ctx context.Context, kind domain.TenantKind) ([]domain.Permission, error) {
	var models []permissionModel
	query := r.db.WithContext(ctx).Order("kind ASC, key ASC")
	if kind != "" {
		query = query.Where("kind = ?", string(kind))
	}
	if err := query.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	out := make([]domain.Permission, len(models))
	for i, m := range models {
		out[i] = m.toDomain()
	}
	return out, nil
}

func (r *roleRepository) FindPermission(ctx context.Context, kind domain.TenantKind, key string) (*domain.Permission, error) {
	var model permissionModel
	err := r.db.WithContext(ctx).Where("kind = ? AND key = ?", string(kind), key).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	permission := model.toDomain()
	return &permission, nil
}

func (r *roleRepository) CreatePermission(ctx context.Context, permission *domain.Permission) (*domain.Permission, error) {
	model := permissionModel{
		Kind: string(permission.Kind), Key: permission.Key, Description: permission.Description,
		CreatedAt: permission.CreatedAt, UpdatedAt: permission.UpdatedAt,
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return r.FindPermission(ctx, permission.Kind, permission.Key)
}

func (r *roleRepository) UpdatePermission(ctx context.Context, kind domain.TenantKind, key string, patch domain.PermissionPatch) (*domain.Permission, error) {
	columns := map[string]any{"updated_at": time.Now()}
	if patch.Description != nil {
		columns["description"] = *patch.Description
	}
	if err := r.db.WithContext(ctx).Model(&permissionModel{}).Where("kind = ? AND key = ?", string(kind), key).Updates(columns).Error; err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return r.FindPermission(ctx, kind, key)
}

func (r *roleRepository) DeletePermission(ctx context.Context, kind domain.TenantKind, key string) error {
	if err := r.db.WithContext(ctx).Where("kind = ? AND key = ?", string(kind), key).Delete(&permissionModel{}).Error; err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	return nil
}

func (r *roleRepository) PermissionGranted(ctx context.Context, kind domain.TenantKind, key string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&rolePermissionModel{}).
		Where("kind = ? AND permission_key = ?", string(kind), key).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("database error: %w", err)
	}
	return count > 0, nil
}
