package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRole_PlatformTier(t *testing.T) {
	tests := []struct {
		role     Role
		tier     Tier
		platform bool
	}{
		{RoleSuper, TierSuper, true},
		{RoleService, TierService, true},
		{RoleGuest, TierGuest, true},
		{RoleAdmin, "", false},
		{RoleUser, "", false},
		{Role("LEGACY_ADMIN"), "", false},
		{Role(""), "", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			tier, ok := tt.role.PlatformTier()
			assert.Equal(t, tt.platform, ok)
			assert.Equal(t, tt.tier, tier)
			assert.Equal(t, tt.platform, tt.role.IsPlatform())
		})
	}
}

func TestRole_IsValidName(t *testing.T) {
	assert.True(t, Role("LAB_TECHNICIAN").IsValidName())
	assert.True(t, Role("ADMIN2").IsValidName())
	assert.False(t, Role("").IsValidName())
	assert.False(t, Role("lab").IsValidName(), "names are upper case")
	assert.False(t, Role("2ND").IsValidName())
	assert.False(t, Role("A B").IsValidName())
	assert.False(t, Role("A"+string(make([]byte, 50))).IsValidName())
}

func TestTier_IsKindTier(t *testing.T) {
	assert.True(t, TierAdmin.IsKindTier())
	assert.True(t, TierMember.IsKindTier())
	assert.True(t, TierGuest.IsKindTier())
	assert.False(t, TierSuper.IsKindTier(), "SUPER is a platform tier")
	assert.False(t, TierService.IsKindTier(), "SERVICE is a platform tier")
	assert.False(t, Tier("ROOT").IsKindTier())
}

func TestTier_CanAssign(t *testing.T) {
	tests := []struct {
		name   string
		caller Tier
		target Tier
		want   bool
	}{
		{"SUPER may assign SUPER", TierSuper, TierSuper, true},
		{"SUPER may assign GUEST", TierSuper, TierGuest, true},
		{"SERVICE may not assign SUPER", TierService, TierSuper, false},
		{"SERVICE may assign SERVICE", TierService, TierService, true},
		{"SERVICE may assign ADMIN", TierService, TierAdmin, true},
		{"ADMIN may not assign SUPER", TierAdmin, TierSuper, false},
		{"ADMIN may not assign SERVICE", TierAdmin, TierService, false},
		{"ADMIN may not assign ADMIN", TierAdmin, TierAdmin, false},
		{"ADMIN may assign MEMBER", TierAdmin, TierMember, true},
		{"ADMIN may assign GUEST", TierAdmin, TierGuest, true},
		{"MEMBER may not assign GUEST", TierMember, TierGuest, false},
		{"GUEST may not assign GUEST", TierGuest, TierGuest, false},
		{"nobody may assign an unknown tier", TierSuper, Tier("ROOT"), false},
		{"nobody may assign an empty tier", TierSuper, Tier(""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caller.CanAssign(tt.target))
		})
	}
}

func TestIsValidPermissionKey(t *testing.T) {
	assert.True(t, IsValidPermissionKey("result:approve"))
	assert.True(t, IsValidPermissionKey("device.calibrate"))
	assert.False(t, IsValidPermissionKey(""))
	assert.False(t, IsValidPermissionKey("Result:approve"))
	assert.False(t, IsValidPermissionKey("result approve"))
	assert.False(t, IsValidPermissionKey("result/approve"))
}

func TestTenantKind_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		kind  TenantKind
		valid bool
	}{
		{"HOSPITAL", TenantKindHospital, true},
		{"LAB", TenantKindLab, true},
		{"FACTORY", TenantKindFactory, true},
		{"CLINIC", TenantKindClinic, true},
		{"PHARMACY", TenantKindPharmacy, true},
		{"OTHER", TenantKindOther, true},
		{"LEGACY is a flag, not a kind", TenantKind("LEGACY"), false},
		{"empty", TenantKind(""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.kind.IsValid())
		})
	}
}

func TestActor_InDepartment(t *testing.T) {
	a := &Actor{DepartmentIDs: []string{"D1", "D2"}}
	assert.True(t, a.InDepartment("D2"))
	assert.False(t, a.InDepartment("D3"))
	assert.False(t, (&Actor{}).InDepartment("D1"))
}

func TestUser_LinkedDepartmentIDs(t *testing.T) {
	u := User{Departments: []Department{{ID: "D1"}, {ID: "D2"}}}
	assert.Equal(t, []string{"D1", "D2"}, u.LinkedDepartmentIDs())
	assert.Empty(t, (&User{}).LinkedDepartmentIDs())
}

func TestActor_IsAdminTier(t *testing.T) {
	admin := map[Tier]bool{TierSuper: true, TierService: true, TierAdmin: true}
	for _, tier := range []Tier{TierSuper, TierService, TierAdmin, TierMember, TierGuest, Tier("")} {
		t.Run(string(tier), func(t *testing.T) {
			// The role name is irrelevant: only the tier counts.
			assert.Equal(t, admin[tier], (&Actor{Role: RoleAdmin, Tier: tier}).IsAdminTier())
		})
	}
}

func TestActor_NilIsUnprivileged(t *testing.T) {
	var a *Actor
	assert.False(t, a.IsAdminTier())
	assert.False(t, a.CanAssign(TierGuest))
}

func TestActor_CanAssign_DelegatesToTier(t *testing.T) {
	assert.True(t, (&Actor{Tier: TierService}).CanAssign(TierAdmin))
	assert.False(t, (&Actor{Tier: TierAdmin}).CanAssign(TierAdmin))
}

func TestPlatformRole(t *testing.T) {
	def := PlatformRole(RoleService)
	if assert.NotNil(t, def) {
		assert.Equal(t, TierService, def.Tier)
		assert.Empty(t, def.Permissions)
		assert.NotNil(t, def.Permissions)
	}
	assert.Nil(t, PlatformRole(RoleAdmin), "ADMIN is a catalogue role")
}
