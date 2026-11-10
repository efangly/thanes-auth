//go:build integration

package database

import (
	"context"
	"testing"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgres_RoleCatalogue(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()
	roles := NewRoleRepository(db)

	// Migration 00003 seeds ADMIN and USER for every kind.
	for _, kind := range []domain.TenantKind{domain.TenantKindHospital, domain.TenantKindLab, domain.TenantKindOther} {
		admin, err := roles.FindRole(ctx, kind, domain.RoleAdmin)
		require.NoError(t, err)
		require.NotNil(t, admin, kind)
		assert.Equal(t, domain.TierAdmin, admin.Tier)
		user, err := roles.FindRole(ctx, kind, domain.RoleUser)
		require.NoError(t, err)
		require.NotNil(t, user, kind)
		assert.Equal(t, domain.TierMember, user.Tier)
		assert.NotNil(t, user.Permissions)
	}

	_, err := roles.CreatePermission(ctx, &domain.Permission{Kind: domain.TenantKindLab, Key: "rt:approve"})
	require.NoError(t, err)
	_, err = roles.CreatePermission(ctx, &domain.Permission{Kind: domain.TenantKindLab, Key: "rt:view"})
	require.NoError(t, err)

	created, err := roles.CreateRole(ctx, &domain.RoleDefinition{
		Kind: domain.TenantKindLab, Name: "RT_APPROVER", Tier: domain.TierMember, Permissions: []string{"rt:view", "rt:approve"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"rt:approve", "rt:view"}, created.Permissions, "sorted")

	missing, err := roles.FindRole(ctx, domain.TenantKindFactory, "RT_APPROVER")
	require.NoError(t, err)
	assert.Nil(t, missing, "a role belongs to one kind")

	only := []string{"rt:approve"}
	updated, err := roles.UpdateRole(ctx, domain.TenantKindLab, "RT_APPROVER", domain.RolePatch{Permissions: &only})
	require.NoError(t, err)
	assert.Equal(t, only, updated.Permissions)
	assert.Equal(t, domain.TierMember, updated.Tier)

	granted, err := roles.PermissionGranted(ctx, domain.TenantKindLab, "rt:approve")
	require.NoError(t, err)
	assert.True(t, granted)
	assert.Error(t, roles.DeletePermission(ctx, domain.TenantKindLab, "rt:approve"), "the foreign key refuses a granted permission")

	// A soft-deleted user in a soft-deleted tenant still holds the role.
	tenants := NewTenantRepository(db)
	users := NewUserRepository(db)
	_, err = tenants.Create(ctx, &domain.Tenant{ID: "rt-lab", Name: "RT Lab", Kind: domain.TenantKindLab})
	require.NoError(t, err)
	_, err = users.Create(ctx, &domain.User{ID: "rt-u1", TenantID: "rt-lab", Username: "rt-approver", Password: "x", Role: "RT_APPROVER", Status: true})
	require.NoError(t, err)
	_, err = users.Delete(ctx, "rt-u1", "test")
	require.NoError(t, err)
	_, err = tenants.Delete(ctx, "rt-lab", "test")
	require.NoError(t, err)

	held, err := roles.RoleHeld(ctx, domain.TenantKindLab, "RT_APPROVER")
	require.NoError(t, err)
	assert.True(t, held)
	held, err = roles.RoleHeld(ctx, domain.TenantKindFactory, "RT_APPROVER")
	require.NoError(t, err)
	assert.False(t, held)
	inTenant, err := roles.RolesHeldInTenant(ctx, "rt-lab")
	require.NoError(t, err)
	assert.Equal(t, []domain.Role{"RT_APPROVER"}, inTenant)

	// A role nobody holds can go, and its grants with it.
	_, err = roles.CreateRole(ctx, &domain.RoleDefinition{Kind: domain.TenantKindLab, Name: "RT_SPARE", Tier: domain.TierGuest, Permissions: []string{"rt:view"}})
	require.NoError(t, err)
	require.NoError(t, roles.DeleteRole(ctx, domain.TenantKindLab, "RT_SPARE"))
	gone, err := roles.FindRole(ctx, domain.TenantKindLab, "RT_SPARE")
	require.NoError(t, err)
	assert.Nil(t, gone)
	granted, err = roles.PermissionGranted(ctx, domain.TenantKindLab, "rt:view")
	require.NoError(t, err)
	assert.False(t, granted)
	require.NoError(t, roles.DeletePermission(ctx, domain.TenantKindLab, "rt:view"))

	// The schema keeps platform roles and tiers out of the catalogue.
	_, err = roles.CreateRole(ctx, &domain.RoleDefinition{Kind: domain.TenantKindLab, Name: domain.RoleSuper, Tier: domain.TierAdmin})
	assert.Error(t, err)
	_, err = roles.CreateRole(ctx, &domain.RoleDefinition{Kind: domain.TenantKindLab, Name: "RT_ROOT", Tier: domain.TierSuper})
	assert.Error(t, err)
}
