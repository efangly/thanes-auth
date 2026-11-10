package services

import (
	"context"
	"testing"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rules of ADR 0006 as the user, tenant and auth services apply them. T1
// is a laboratory and T2 a factory; LAB defines APPROVER (MEMBER, granting
// result:approve) and LEAD (ADMIN); FACTORY defines LEAD as a MEMBER.

func kindedTenants(_ context.Context, id string) (*domain.Tenant, error) {
	switch id {
	case "T1":
		return &domain.Tenant{ID: id, Kind: domain.TenantKindLab}, nil
	case "T2":
		return &domain.Tenant{ID: id, Kind: domain.TenantKindFactory}, nil
	}
	return nil, nil
}

func kindedCatalogue(_ context.Context, kind domain.TenantKind, name domain.Role) (*domain.RoleDefinition, error) {
	if def := defaultCatalogueRole(kind, name); def != nil {
		return def, nil
	}
	switch {
	case kind == domain.TenantKindLab && name == "APPROVER":
		return &domain.RoleDefinition{Kind: kind, Name: name, Tier: domain.TierMember, Permissions: []string{"result:approve"}}, nil
	case kind == domain.TenantKindLab && name == "LEAD":
		return &domain.RoleDefinition{Kind: kind, Name: name, Tier: domain.TierAdmin, Permissions: []string{}}, nil
	case kind == domain.TenantKindFactory && name == "LEAD":
		return &domain.RoleDefinition{Kind: kind, Name: name, Tier: domain.TierMember, Permissions: []string{}}, nil
	}
	return nil, nil
}

func newKindedUserFixture(repo *mockUserRepo) *userFixture {
	f := newUserFixture(repo)
	f.tenants.FindByIDFn = kindedTenants
	f.tenants.FindAnyByIDFn = kindedTenants
	f.roles.FindRoleFn = kindedCatalogue
	return f
}

var t1Admin = &domain.Actor{ID: "A1", Role: domain.RoleAdmin, Tier: domain.TierAdmin, TenantID: "T1", TenantKind: domain.TenantKindLab}

func TestUserService_Create_RoleMustExistForTheTenantKind(t *testing.T) {
	f := newKindedUserFixture(&mockUserRepo{CreateFn: echoUser})
	ctx := context.Background()

	_, err := f.svc.Create(ctx, &domain.User{Password: testPassword, Username: "u1", TenantID: "T2", Role: "APPROVER"}, superCaller)
	assert.EqualError(t, err, "invalid role: APPROVER", "APPROVER is a LAB role")

	user, err := f.svc.Create(ctx, &domain.User{Password: testPassword, Username: "u2", TenantID: "T1", Role: "APPROVER"}, superCaller)
	require.NoError(t, err)
	assert.Equal(t, domain.Role("APPROVER"), user.Role)
}

func TestUserService_Create_CeilingIsTheTierNotThePermissions(t *testing.T) {
	f := newKindedUserFixture(&mockUserRepo{CreateFn: echoUser})
	ctx := context.Background()

	// A MEMBER role that grants permissions is within a tenant admin's ceiling...
	_, err := f.svc.Create(ctx, &domain.User{Password: testPassword, Username: "u1", TenantID: "T1", Role: "APPROVER"}, t1Admin)
	require.NoError(t, err)
	// ...an ADMIN-tier role of any name is not.
	_, err = f.svc.Create(ctx, &domain.User{Password: testPassword, Username: "u2", TenantID: "T1", Role: "LEAD"}, t1Admin)
	assert.EqualError(t, err, "you cannot assign role LEAD")
}

func TestUserService_Update_TargetJudgedByItsRolesTier(t *testing.T) {
	tests := []struct {
		name   string
		role   domain.Role
		caller *domain.Actor
		want   string
	}{
		{"admin may change a MEMBER-tier holder", "APPROVER", t1Admin, ""},
		{"admin may not change an ADMIN-tier holder", "LEAD", t1Admin, "you do not have permission to modify this user"},
		{"an unknown role counts as ADMIN", "GONE", t1Admin, "you do not have permission to modify this user"},
		{"SERVICE may repair an unknown role", "GONE", serviceAct, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newKindedUserFixture(&mockUserRepo{
				FindByIDFn: findUserIn(tt.role, "T1"),
				UpdateFn: func(_ context.Context, id string, _ domain.UserPatch) (*domain.User, error) {
					return &domain.User{ID: id}, nil
				},
			})
			display := "x"
			_, err := f.svc.Update(context.Background(), "U9", domain.UserPatch{Display: &display}, nil, tt.caller)
			if tt.want == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.want)
			}
		})
	}
}

func TestUserService_Update_MovingToAnotherKindNeedsARole(t *testing.T) {
	updated := false
	f := newKindedUserFixture(&mockUserRepo{
		FindByIDFn: findUserIn("APPROVER", "T1"),
		UpdateFn: func(_ context.Context, id string, _ domain.UserPatch) (*domain.User, error) {
			updated = true
			return &domain.User{ID: id}, nil
		},
	})
	ctx := context.Background()
	t2, none := "T2", []string{}

	_, err := f.svc.Update(ctx, "U9", domain.UserPatch{TenantID: &t2, DepartmentIDs: &none}, nil, serviceAct)
	assert.EqualError(t, err, "role is required when changing to a tenant of another kind")

	missing := domain.Role("APPROVER")
	_, err = f.svc.Update(ctx, "U9", domain.UserPatch{TenantID: &t2, DepartmentIDs: &none, Role: &missing}, nil, serviceAct)
	assert.EqualError(t, err, "invalid role: APPROVER", "the role must exist in the new kind")
	assert.False(t, updated)

	user := domain.RoleUser
	_, err = f.svc.Update(ctx, "U9", domain.UserPatch{TenantID: &t2, DepartmentIDs: &none, Role: &user}, nil, serviceAct)
	require.NoError(t, err)
	assert.True(t, updated)
}

func TestUserService_Update_PlatformRoleMovesWithoutANewRole(t *testing.T) {
	f := newKindedUserFixture(&mockUserRepo{
		FindByIDFn: findUserIn(domain.RoleGuest, "T1"),
		UpdateFn: func(_ context.Context, id string, _ domain.UserPatch) (*domain.User, error) {
			return &domain.User{ID: id}, nil
		},
	})
	t2, none := "T2", []string{}
	_, err := f.svc.Update(context.Background(), "U9", domain.UserPatch{TenantID: &t2, DepartmentIDs: &none}, nil, serviceAct)
	assert.NoError(t, err)
}

func TestUserService_Update_SameNameInTheNewKindIsRechecked(t *testing.T) {
	// LEAD is ADMIN in LAB but MEMBER in FACTORY; the check uses the new kind.
	var gotRole domain.Role
	f := newKindedUserFixture(&mockUserRepo{
		FindByIDFn: findUserIn("LEAD", "T1"),
		UpdateFn: func(_ context.Context, id string, p domain.UserPatch) (*domain.User, error) {
			gotRole = *p.Role
			return &domain.User{ID: id}, nil
		},
	})
	t2, none, lead := "T2", []string{}, domain.Role("LEAD")
	_, err := f.svc.Update(context.Background(), "U9", domain.UserPatch{TenantID: &t2, DepartmentIDs: &none, Role: &lead}, nil, serviceAct)
	require.NoError(t, err)
	assert.Equal(t, lead, gotRole)
}

// --- tenant kind change ---

func TestTenantService_Update_KindChangeKeepsEveryHeldRoleMeaningful(t *testing.T) {
	tests := []struct {
		name string
		held []domain.Role
		want string
	}{
		{"default and platform roles move freely", []domain.Role{domain.RoleAdmin, domain.RoleUser, domain.RoleGuest, domain.RoleSuper}, ""},
		{"a role the new kind lacks", []domain.Role{"APPROVER"}, "users of this tenant hold role APPROVER, which tenant kind FACTORY does not have with the same tier"},
		{"a role with another tier there", []domain.Role{"LEAD"}, "users of this tenant hold role LEAD, which tenant kind FACTORY does not have with the same tier"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated := false
			repo := &mockTenantRepo{
				FindByIDFn: kindedTenants,
				UpdateFn: func(_ context.Context, id string, _ domain.TenantPatch) (*domain.Tenant, error) {
					updated = true
					return &domain.Tenant{ID: id}, nil
				},
			}
			roles := &mockRoleRepo{
				FindRoleFn:          kindedCatalogue,
				RolesHeldInTenantFn: func(context.Context, string) ([]domain.Role, error) { return tt.held, nil },
			}
			svc := NewTenantService(repo, roles, newMockCache(), newMockUpload(), newMockMessaging(), newMockAuditService())
			factory := domain.TenantKindFactory
			_, err := svc.Update(context.Background(), "T1", domain.TenantPatch{Kind: &factory}, nil, superCaller)
			if tt.want == "" {
				assert.NoError(t, err)
				assert.True(t, updated)
			} else {
				assert.EqualError(t, err, tt.want)
				assert.False(t, updated)
			}
		})
	}
}

func TestTenantService_Update_SameKindSkipsTheCheck(t *testing.T) {
	repo := &mockTenantRepo{
		FindByIDFn: kindedTenants,
		UpdateFn: func(_ context.Context, id string, _ domain.TenantPatch) (*domain.Tenant, error) {
			return &domain.Tenant{ID: id}, nil
		},
	}
	roles := &mockRoleRepo{RolesHeldInTenantFn: func(context.Context, string) ([]domain.Role, error) {
		t.Fatal("an unchanged kind needs no check")
		return nil, nil
	}}
	svc := NewTenantService(repo, roles, newMockCache(), newMockUpload(), newMockMessaging(), newMockAuditService())
	lab := domain.TenantKindLab
	_, err := svc.Update(context.Background(), "T1", domain.TenantPatch{Kind: &lab}, nil, superCaller)
	assert.NoError(t, err)
}

// --- tokens ---

func TestAuthService_Login_CarriesTierKindAndPermissions(t *testing.T) {
	tokens := &fakeTokens{}
	svc := NewAuthService(&mockUserService{}, &mockRoleRepo{FindRoleFn: kindedCatalogue}, newMockCache(), newFakeSessions(),
		newMockUpload(), tokens, &fakeHasher{}, newRecordedAudit())

	user := &domain.User{ID: "U1", Role: "APPROVER", TenantID: "T1", Tenant: &domain.Tenant{ID: "T1", Kind: domain.TenantKindLab}}
	result, err := svc.Login(context.Background(), user)
	require.NoError(t, err)
	assert.Equal(t, domain.TierMember, result.Tier)
	assert.Equal(t, domain.TenantKindLab, result.TenantKind)
	assert.Equal(t, []string{"result:approve"}, result.Permissions)
	require.Len(t, tokens.issued, 1)
	assert.Equal(t, domain.TierMember, tokens.issued[0].Tier)
	assert.Equal(t, []string{"result:approve"}, tokens.issued[0].Permissions)
}

func TestAuthService_Login_UnknownRoleFailsClosedToGuest(t *testing.T) {
	tokens := &fakeTokens{}
	svc := NewAuthService(&mockUserService{}, &mockRoleRepo{FindRoleFn: kindedCatalogue}, newMockCache(), newFakeSessions(),
		newMockUpload(), tokens, &fakeHasher{}, newRecordedAudit())

	user := &domain.User{ID: "U1", Role: "LEAD", TenantID: "T9", Tenant: &domain.Tenant{ID: "T9", Kind: domain.TenantKindClinic}}
	_, err := svc.Login(context.Background(), user)
	require.NoError(t, err)
	require.Len(t, tokens.issued, 1)
	assert.Equal(t, domain.TierGuest, tokens.issued[0].Tier)
	assert.Empty(t, tokens.issued[0].Permissions)
}

func TestAuthService_Refresh_RebuildsPermissionsFromTheCatalogue(t *testing.T) {
	perms := []string{"result:approve"}
	roles := &mockRoleRepo{FindRoleFn: func(_ context.Context, kind domain.TenantKind, name domain.Role) (*domain.RoleDefinition, error) {
		return &domain.RoleDefinition{Kind: kind, Name: name, Tier: domain.TierMember, Permissions: perms}, nil
	}}
	userSvc := &mockUserService{FindByIDFn: func(_ context.Context, id string) (*domain.User, error) {
		return &domain.User{ID: id, Role: "APPROVER", Status: true, TenantID: "T1", Tenant: &domain.Tenant{ID: "T1", Kind: domain.TenantKindLab}}, nil
	}}
	tokens := &fakeTokens{}
	svc := NewAuthService(userSvc, roles, newMockCache(), newFakeSessions(), newMockUpload(), tokens, &fakeHasher{}, newRecordedAudit())

	perms = []string{"result:approve", "result:view"} // SUPER changed the role since the last token
	_, err := svc.RefreshTokens(context.Background(), "refresh:U1")
	require.NoError(t, err)
	require.Len(t, tokens.issued, 1)
	assert.Equal(t, []string{"result:approve", "result:view"}, tokens.issued[0].Permissions)
}
