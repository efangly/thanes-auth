package dto

import (
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
)

// CreateRoleRequest is the body of POST /auth/role. The tier is fixed for the
// life of the role.
type CreateRoleRequest struct {
	Kind        domain.TenantKind `json:"kind" validate:"required,max=20"`
	Name        domain.Role       `json:"name" validate:"required,max=50"`
	Tier        domain.Tier       `json:"tier" validate:"required,max=10"`
	Description *string           `json:"description,omitempty" validate:"omitempty,max=255"`
	Permissions []string          `json:"permissions,omitempty" validate:"omitempty,max=200,dive,max=100"`
}

// ToRole converts the DTO to a catalogue role.
func (r *CreateRoleRequest) ToRole() *domain.RoleDefinition {
	return &domain.RoleDefinition{
		Kind: r.Kind, Name: r.Name, Tier: r.Tier, Description: r.Description, Permissions: r.Permissions,
	}
}

// UpdateRoleRequest is the body of PUT /auth/role/:kind/:name. It has no tier:
// a role's tier cannot change.
type UpdateRoleRequest struct {
	Description *string   `json:"description,omitempty" validate:"omitempty,max=255"`
	Permissions *[]string `json:"permissions,omitempty" validate:"omitempty,max=200,dive,max=100"`
}

// ToPatch converts the update DTO to a partial update; unset fields stay nil.
func (r *UpdateRoleRequest) ToPatch() domain.RolePatch {
	return domain.RolePatch{Description: r.Description, Permissions: r.Permissions}
}

// CreatePermissionRequest is the body of POST /auth/permission.
type CreatePermissionRequest struct {
	Kind        domain.TenantKind `json:"kind" validate:"required,max=20"`
	Key         string            `json:"key" validate:"required,max=100"`
	Description *string           `json:"description,omitempty" validate:"omitempty,max=255"`
}

// ToPermission converts the DTO to a permission.
func (r *CreatePermissionRequest) ToPermission() *domain.Permission {
	return &domain.Permission{Kind: r.Kind, Key: r.Key, Description: r.Description}
}

// UpdatePermissionRequest is the body of PUT /auth/permission/:kind/:key.
type UpdatePermissionRequest struct {
	Description *string `json:"description,omitempty" validate:"omitempty,max=255"`
}

// ToPatch converts the update DTO to a partial update; unset fields stay nil.
func (r *UpdatePermissionRequest) ToPatch() domain.PermissionPatch {
	return domain.PermissionPatch{Description: r.Description}
}

// RoleResponse is a catalogue role.
type RoleResponse struct {
	Kind        domain.TenantKind `json:"kind"`
	Name        domain.Role       `json:"name"`
	Tier        domain.Tier       `json:"tier"`
	Description *string           `json:"description"`
	Permissions []string          `json:"permissions"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
}

// PermissionResponse is a catalogue permission.
type PermissionResponse struct {
	Kind        domain.TenantKind `json:"kind"`
	Key         string            `json:"key"`
	Description *string           `json:"description"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
}

// FromRole converts a catalogue role to its JSON shape.
func FromRole(r *domain.RoleDefinition) RoleResponse {
	return RoleResponse{
		Kind: r.Kind, Name: r.Name, Tier: r.Tier, Description: r.Description,
		Permissions: nonNil(r.Permissions), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

// FromRoles converts catalogue roles to their JSON shape.
func FromRoles(roles []domain.RoleDefinition) []RoleResponse {
	out := make([]RoleResponse, len(roles))
	for i := range roles {
		out[i] = FromRole(&roles[i])
	}
	return out
}

// FromPermission converts a permission to its JSON shape.
func FromPermission(p *domain.Permission) PermissionResponse {
	return PermissionResponse{Kind: p.Kind, Key: p.Key, Description: p.Description, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

// FromPermissions converts permissions to their JSON shape.
func FromPermissions(permissions []domain.Permission) []PermissionResponse {
	out := make([]PermissionResponse, len(permissions))
	for i := range permissions {
		out[i] = FromPermission(&permissions[i])
	}
	return out
}
