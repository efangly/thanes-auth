package domain

import (
	"regexp"
	"time"
)

// Role is the name of the job a user holds (GLOSSARY "Role"). It is either a
// platform role, the same for every tenant kind, or a role defined for one
// tenant kind in the role catalogue (ADR 0006). The name alone does not say
// what the role may do: resolve it to a RoleDefinition for its tier.
type Role string

// Platform roles exist for every tenant kind and are not in the catalogue.
const (
	RoleSuper   Role = "SUPER"
	RoleService Role = "SERVICE"
	RoleGuest   Role = "GUEST"
)

// Default roles every tenant kind's catalogue starts with (migration 00003).
// They are ordinary catalogue roles and may be given permissions.
const (
	RoleAdmin Role = "ADMIN"
	RoleUser  Role = "USER"
)

var roleNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,49}$`)

// IsValidName reports whether r is acceptable as a role name.
func (r Role) IsValidName() bool { return roleNamePattern.MatchString(string(r)) }

// PlatformTier returns the tier of a platform role; ok is false for any
// other role.
func (r Role) PlatformTier() (tier Tier, ok bool) {
	switch r {
	case RoleSuper:
		return TierSuper, true
	case RoleService:
		return TierService, true
	case RoleGuest:
		return TierGuest, true
	}
	return "", false
}

// IsPlatform reports whether r is a platform role.
func (r Role) IsPlatform() bool {
	_, ok := r.PlatformTier()
	return ok
}

// Tier is the fixed level of authority a role carries, and the only thing
// this service decides by (GLOSSARY "Tier").
type Tier string

const (
	TierSuper   Tier = "SUPER"
	TierService Tier = "SERVICE"
	TierAdmin   Tier = "ADMIN"
	TierMember  Tier = "MEMBER"
	TierGuest   Tier = "GUEST"
)

func (t Tier) IsValid() bool {
	switch t {
	case TierSuper, TierService, TierAdmin, TierMember, TierGuest:
		return true
	}
	return false
}

// IsKindTier reports whether a catalogue role may carry t. SUPER and SERVICE
// belong to the platform roles alone.
func (t Tier) IsKindTier() bool {
	switch t {
	case TierAdmin, TierMember, TierGuest:
		return true
	}
	return false
}

// IsAdminTier reports whether t may act on users other than themselves.
func (t Tier) IsAdminTier() bool {
	switch t {
	case TierSuper, TierService, TierAdmin:
		return true
	}
	return false
}

// CanAssign reports whether a caller of tier t may give a role of tier target
// to a user — and, by the same rule, may modify or delete a user who already
// holds one. This is the role ceiling (GLOSSARY "Role ceiling"). Which
// permissions the role grants does not matter.
func (t Tier) CanAssign(target Tier) bool {
	if !target.IsValid() {
		return false
	}
	switch t {
	case TierSuper:
		return true
	case TierService:
		return target != TierSuper
	case TierAdmin:
		return target == TierMember || target == TierGuest
	}
	return false
}

// RoleDefinition is a role as the catalogue defines it: its tier and the
// permissions it grants. Platform roles have a definition with no kind and no
// permissions (see PlatformRole).
type RoleDefinition struct {
	Kind        TenantKind
	Name        Role
	Tier        Tier
	Description *string
	// Permissions are the keys of the permissions the role grants, sorted.
	Permissions []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PlatformRole returns the definition of a platform role, or nil for any
// other role.
func PlatformRole(r Role) *RoleDefinition {
	tier, ok := r.PlatformTier()
	if !ok {
		return nil
	}
	return &RoleDefinition{Name: r, Tier: tier, Permissions: []string{}}
}

// Permission is a named action in another SMtrack system that a role of the
// same tenant kind may grant. This service never checks it; it is handed on
// in the token.
type Permission struct {
	Kind        TenantKind
	Key         string
	Description *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

var permissionKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,99}$`)

// IsValidPermissionKey reports whether key is acceptable as a permission key,
// such as "result:approve".
func IsValidPermissionKey(key string) bool { return permissionKeyPattern.MatchString(key) }

// RolePatch is a partial update of a catalogue role. Its tier cannot change.
type RolePatch struct {
	Description *string
	// Permissions replaces the granted permissions when set.
	Permissions *[]string
}

// PermissionPatch is a partial update of a permission.
type PermissionPatch struct {
	Description *string
}
