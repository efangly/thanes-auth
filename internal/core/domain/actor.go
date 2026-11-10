package domain

// Actor is the user performing the current request, as identified by their
// access token. A nil *Actor means there is no authenticated user.
type Actor struct {
	ID   string
	Name string
	Role Role
	// Tier is what this service decides by; Role and Permissions are carried
	// for the other systems (ADR 0006).
	Tier          Tier
	TenantID      string
	TenantKind    TenantKind
	DepartmentIDs []string
	Permissions   []string
}

// IsAdminTier reports whether the actor may act on records belonging to other
// users. Everyone else is restricted to their own account.
func (a *Actor) IsAdminTier() bool {
	if a == nil {
		return false
	}
	return a.Tier.IsAdminTier()
}

// CanAssign reports whether the actor may give a role of tier to a user, or
// modify or delete a user whose role has it. See Tier.CanAssign.
func (a *Actor) CanAssign(tier Tier) bool {
	if a == nil {
		return false
	}
	return a.Tier.CanAssign(tier)
}

// InDepartment reports whether the actor is linked to the department.
func (a *Actor) InDepartment(id string) bool {
	for _, d := range a.DepartmentIDs {
		if d == id {
			return true
		}
	}
	return false
}
