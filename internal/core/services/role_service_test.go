package services

import (
	"context"
	"testing"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	labAdmin   = &domain.Actor{ID: "A1", Role: domain.RoleAdmin, Tier: domain.TierAdmin, TenantID: "T1", TenantKind: domain.TenantKindLab}
	labMember  = &domain.Actor{ID: "M1", Role: domain.RoleUser, Tier: domain.TierMember, TenantID: "T1", TenantKind: domain.TenantKindLab}
	serviceAct = &domain.Actor{ID: "S1", Role: domain.RoleService, Tier: domain.TierService}
)

// labPermissions registers result:approve and result:view for LAB only.
func labPermissions(_ context.Context, kind domain.TenantKind, key string) (*domain.Permission, error) {
	if kind == domain.TenantKindLab && (key == "result:approve" || key == "result:view") {
		return &domain.Permission{Kind: kind, Key: key}, nil
	}
	return nil, nil
}

type auditEntry struct {
	entity   domain.AuditEntity
	action   domain.AuditAction
	entityID string
}

// catalogueAudit records what the role service audits.
type catalogueAudit struct {
	*mockAuditService
	entries []auditEntry
}

func (a *catalogueAudit) actions() []domain.AuditAction {
	var out []domain.AuditAction
	for _, e := range a.entries {
		out = append(out, e.action)
	}
	return out
}

func newTestRoleService(repo *mockRoleRepo) (*roleService, *catalogueAudit) {
	audit := &catalogueAudit{}
	audit.mockAuditService = &mockAuditService{RecordFn: func(_ context.Context, e domain.AuditEntity, a domain.AuditAction, id string, _ *domain.Actor, _ any) {
		audit.entries = append(audit.entries, auditEntry{e, a, id})
	}}
	return NewRoleService(repo, audit).(*roleService), audit
}

func TestRoleService_FindRoles_ScopedByTier(t *testing.T) {
	tests := []struct {
		name     string
		caller   *domain.Actor
		asked    domain.TenantKind
		wantKind domain.TenantKind
		reached  bool
	}{
		{"SUPER reads every kind", superCaller, "", "", true},
		{"SERVICE reads a kind", serviceAct, domain.TenantKindFactory, domain.TenantKindFactory, true},
		{"admin reads its own kind by default", labAdmin, "", domain.TenantKindLab, true},
		{"admin reads its own kind", labAdmin, domain.TenantKindLab, domain.TenantKindLab, true},
		{"admin does not read another kind", labAdmin, domain.TenantKindFactory, "", false},
		{"admin without a kind reads nothing", &domain.Actor{ID: "A2", Tier: domain.TierAdmin, TenantID: "T1"}, "", "", false},
		{"member reads nothing", labMember, "", "", false},
		{"no caller reads nothing", nil, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			var gotKind domain.TenantKind
			svc, _ := newTestRoleService(&mockRoleRepo{FindRolesFn: func(_ context.Context, kind domain.TenantKind) ([]domain.RoleDefinition, error) {
				reached, gotKind = true, kind
				return []domain.RoleDefinition{{Name: "X"}}, nil
			}})
			roles, err := svc.FindRoles(context.Background(), tt.asked, tt.caller)
			require.NoError(t, err)
			assert.Equal(t, tt.reached, reached)
			if tt.reached {
				assert.Equal(t, tt.wantKind, gotKind)
				assert.Len(t, roles, 1)
			} else {
				assert.Empty(t, roles)
			}
		})
	}
}

func TestRoleService_FindRoles_RejectsUnknownKind(t *testing.T) {
	svc, _ := newTestRoleService(&mockRoleRepo{})
	_, err := svc.FindRoles(context.Background(), "SPACESHIP", superCaller)
	assert.EqualError(t, err, "invalid tenant kind: SPACESHIP")
}

func TestRoleService_FindRole_OtherKindReadsAsNotFound(t *testing.T) {
	svc, _ := newTestRoleService(&mockRoleRepo{})
	_, err := svc.FindRole(context.Background(), domain.TenantKindFactory, domain.RoleAdmin, labAdmin)
	assert.EqualError(t, err, "role not found")

	role, err := svc.FindRole(context.Background(), domain.TenantKindLab, domain.RoleAdmin, labAdmin)
	require.NoError(t, err)
	assert.Equal(t, domain.TierAdmin, role.Tier)
}

func TestRoleService_OnlySuperChangesTheCatalogue(t *testing.T) {
	ctx := context.Background()
	for _, caller := range []*domain.Actor{nil, serviceAct, labAdmin, labMember} {
		svc, audit := newTestRoleService(&mockRoleRepo{
			CreateRoleFn: func(context.Context, *domain.RoleDefinition) (*domain.RoleDefinition, error) {
				t.Fatal("must not reach the repository")
				return nil, nil
			},
		})
		const denied = "only SUPER can change the role catalogue"
		_, err := svc.CreateRole(ctx, &domain.RoleDefinition{Kind: domain.TenantKindLab, Name: "X", Tier: domain.TierMember}, caller)
		assert.EqualError(t, err, denied)
		_, err = svc.UpdateRole(ctx, domain.TenantKindLab, domain.RoleUser, domain.RolePatch{}, caller)
		assert.EqualError(t, err, denied)
		assert.EqualError(t, svc.RemoveRole(ctx, domain.TenantKindLab, domain.RoleUser, caller), denied)
		_, err = svc.CreatePermission(ctx, &domain.Permission{Kind: domain.TenantKindLab, Key: "a:b"}, caller)
		assert.EqualError(t, err, denied)
		_, err = svc.UpdatePermission(ctx, domain.TenantKindLab, "a:b", domain.PermissionPatch{}, caller)
		assert.EqualError(t, err, denied)
		assert.EqualError(t, svc.RemovePermission(ctx, domain.TenantKindLab, "a:b", caller), denied)
		assert.Empty(t, audit.actions())
	}
}

func TestRoleService_CreateRole_Validation(t *testing.T) {
	tests := []struct {
		name string
		role domain.RoleDefinition
		want string
	}{
		{"unknown kind", domain.RoleDefinition{Kind: "SPACESHIP", Name: "PILOT", Tier: domain.TierMember}, "invalid tenant kind: SPACESHIP"},
		{"bad name", domain.RoleDefinition{Kind: domain.TenantKindLab, Name: "lab tech", Tier: domain.TierMember}, "invalid role name: lab tech"},
		{"platform name", domain.RoleDefinition{Kind: domain.TenantKindLab, Name: domain.RoleGuest, Tier: domain.TierGuest}, "GUEST is a platform role"},
		{"platform tier", domain.RoleDefinition{Kind: domain.TenantKindLab, Name: "ROOT", Tier: domain.TierSuper}, "invalid tier: SUPER"},
		{"unknown tier", domain.RoleDefinition{Kind: domain.TenantKindLab, Name: "ROOT", Tier: "OWNER"}, "invalid tier: OWNER"},
		{"exists", domain.RoleDefinition{Kind: domain.TenantKindLab, Name: domain.RoleAdmin, Tier: domain.TierAdmin}, "role already exists"},
		{"unregistered permission", domain.RoleDefinition{Kind: domain.TenantKindLab, Name: "TECH", Tier: domain.TierMember, Permissions: []string{"device:calibrate"}}, "permission not found: device:calibrate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestRoleService(&mockRoleRepo{FindPermissionFn: labPermissions})
			role := tt.role
			_, err := svc.CreateRole(context.Background(), &role, superCaller)
			assert.EqualError(t, err, tt.want)
		})
	}
}

func TestRoleService_CreateRole_PermissionsOfAnotherKindAreRejected(t *testing.T) {
	svc, _ := newTestRoleService(&mockRoleRepo{FindPermissionFn: labPermissions})
	_, err := svc.CreateRole(context.Background(), &domain.RoleDefinition{
		Kind: domain.TenantKindFactory, Name: "QC", Tier: domain.TierMember, Permissions: []string{"result:approve"},
	}, superCaller)
	assert.EqualError(t, err, "permission not found: result:approve")
}

func TestRoleService_CreateRole_SortsDedupesAndAudits(t *testing.T) {
	var stored *domain.RoleDefinition
	svc, audit := newTestRoleService(&mockRoleRepo{
		FindPermissionFn: labPermissions,
		CreateRoleFn: func(_ context.Context, role *domain.RoleDefinition) (*domain.RoleDefinition, error) {
			stored = role
			return role, nil
		},
	})
	_, err := svc.CreateRole(context.Background(), &domain.RoleDefinition{
		Kind: domain.TenantKindLab, Name: "APPROVER", Tier: domain.TierMember,
		Permissions: []string{"result:view", "result:approve", "result:view"},
	}, superCaller)
	require.NoError(t, err)
	assert.Equal(t, []string{"result:approve", "result:view"}, stored.Permissions)
	assert.False(t, stored.CreatedAt.IsZero())
	assert.Equal(t, []domain.AuditAction{domain.AuditActionCreate}, audit.actions())
	assert.Equal(t, "LAB:APPROVER", audit.entries[0].entityID)
	assert.Equal(t, domain.AuditEntityRole, audit.entries[0].entity)
}

func TestRoleService_UpdateRole(t *testing.T) {
	var gotPatch domain.RolePatch
	svc, audit := newTestRoleService(&mockRoleRepo{
		FindPermissionFn: labPermissions,
		UpdateRoleFn: func(_ context.Context, kind domain.TenantKind, name domain.Role, patch domain.RolePatch) (*domain.RoleDefinition, error) {
			gotPatch = patch
			return &domain.RoleDefinition{Kind: kind, Name: name}, nil
		},
	})
	ctx := context.Background()

	_, err := svc.UpdateRole(ctx, domain.TenantKindLab, "NOBODY", domain.RolePatch{}, superCaller)
	assert.EqualError(t, err, "role not found")

	bad := []string{"device:calibrate"}
	_, err = svc.UpdateRole(ctx, domain.TenantKindLab, domain.RoleUser, domain.RolePatch{Permissions: &bad}, superCaller)
	assert.EqualError(t, err, "permission not found: device:calibrate")

	perms := []string{"result:view", "result:approve"}
	_, err = svc.UpdateRole(ctx, domain.TenantKindLab, domain.RoleUser, domain.RolePatch{Permissions: &perms}, superCaller)
	require.NoError(t, err)
	require.NotNil(t, gotPatch.Permissions)
	assert.Equal(t, []string{"result:approve", "result:view"}, *gotPatch.Permissions)
	assert.Equal(t, []domain.AuditAction{domain.AuditActionUpdate}, audit.actions())
}

func TestRoleService_RemoveRole_RefusedWhileHeld(t *testing.T) {
	deleted := false
	held := true
	svc, audit := newTestRoleService(&mockRoleRepo{
		RoleHeldFn: func(context.Context, domain.TenantKind, domain.Role) (bool, error) { return held, nil },
		DeleteRoleFn: func(context.Context, domain.TenantKind, domain.Role) error {
			deleted = true
			return nil
		},
	})
	ctx := context.Background()

	assert.EqualError(t, svc.RemoveRole(ctx, domain.TenantKindLab, domain.RoleUser, superCaller), "role is still held by users")
	assert.False(t, deleted)

	held = false
	require.NoError(t, svc.RemoveRole(ctx, domain.TenantKindLab, domain.RoleUser, superCaller))
	assert.True(t, deleted)
	assert.Equal(t, []domain.AuditAction{domain.AuditActionDelete}, audit.actions())

	assert.EqualError(t, svc.RemoveRole(ctx, domain.TenantKindLab, "NOBODY", superCaller), "role not found")
}

func TestRoleService_Permissions(t *testing.T) {
	granted := true
	svc, audit := newTestRoleService(&mockRoleRepo{
		FindPermissionFn:    labPermissions,
		PermissionGrantedFn: func(context.Context, domain.TenantKind, string) (bool, error) { return granted, nil },
	})
	ctx := context.Background()

	_, err := svc.CreatePermission(ctx, &domain.Permission{Kind: domain.TenantKindLab, Key: "Result Approve"}, superCaller)
	assert.EqualError(t, err, "invalid permission key: Result Approve")
	_, err = svc.CreatePermission(ctx, &domain.Permission{Kind: domain.TenantKindLab, Key: "result:approve"}, superCaller)
	assert.EqualError(t, err, "permission already exists")
	_, err = svc.CreatePermission(ctx, &domain.Permission{Kind: "SPACESHIP", Key: "a:b"}, superCaller)
	assert.EqualError(t, err, "invalid tenant kind: SPACESHIP")
	created, err := svc.CreatePermission(ctx, &domain.Permission{Kind: domain.TenantKindLab, Key: "device:calibrate"}, superCaller)
	require.NoError(t, err)
	assert.Equal(t, "device:calibrate", created.Key)

	assert.EqualError(t, svc.RemovePermission(ctx, domain.TenantKindLab, "result:approve", superCaller), "permission is still granted by roles")
	granted = false
	require.NoError(t, svc.RemovePermission(ctx, domain.TenantKindLab, "result:approve", superCaller))
	assert.EqualError(t, svc.RemovePermission(ctx, domain.TenantKindLab, "nope", superCaller), "permission not found")

	assert.Equal(t, []domain.AuditAction{domain.AuditActionCreate, domain.AuditActionDelete}, audit.actions())
}
