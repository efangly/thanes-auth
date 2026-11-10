package services

import (
	"context"
	"testing"
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserService_AccessReport_ScopedUncachedAndAudited(t *testing.T) {
	var gotFilter ports.UserFilter
	repo := &mockUserRepo{FindAllFn: func(_ context.Context, f ports.UserFilter) ([]domain.User, error) {
		gotFilter = f
		return []domain.User{{ID: "U1", Password: "hash", TenantID: "T1"}}, nil
	}}
	f := newUserFixture(repo)
	var actions []domain.AuditAction
	f.audit.RecordFn = func(_ context.Context, _ domain.AuditEntity, a domain.AuditAction, _ string, _ *domain.Actor, _ any) {
		actions = append(actions, a)
	}

	users, err := f.svc.AccessReport(context.Background(), &domain.Actor{ID: "A1", Role: domain.RoleAdmin, Tier: tierFor(domain.RoleAdmin), TenantID: "T1"})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Empty(t, users[0].User.Password)
	assert.Equal(t, "T1", gotFilter.TenantID, "an admin's report stays inside the tenant")
	assert.Equal(t, []domain.AuditAction{domain.AuditActionAccessReport}, actions)
	assert.Empty(t, f.cache.stored, "the report must not be served from, or written to, the cache")
}

func TestUserService_AccessReport_ShowsTierAndPermissions(t *testing.T) {
	lab := &domain.Tenant{ID: "T1", Kind: domain.TenantKindLab}
	repo := &mockUserRepo{FindAllFn: func(context.Context, ports.UserFilter) ([]domain.User, error) {
		return []domain.User{
			{ID: "U1", TenantID: "T1", Tenant: lab, Role: "APPROVER"},
			{ID: "U2", TenantID: "T1", Tenant: lab, Role: "APPROVER"},
			{ID: "U3", TenantID: "T1", Tenant: lab, Role: domain.RoleGuest},
			{ID: "U4", TenantID: "T1", Tenant: lab, Role: "GONE"},
		}, nil
	}}
	f := newUserFixture(repo)
	lookups := 0
	f.roles.FindRoleFn = func(_ context.Context, kind domain.TenantKind, name domain.Role) (*domain.RoleDefinition, error) {
		lookups++
		if kind == domain.TenantKindLab && name == "APPROVER" {
			return &domain.RoleDefinition{Kind: kind, Name: name, Tier: domain.TierMember, Permissions: []string{"result:approve"}}, nil
		}
		return nil, nil
	}

	entries, err := f.svc.AccessReport(context.Background(), superCaller)
	require.NoError(t, err)
	require.Len(t, entries, 4)
	assert.Equal(t, domain.TierMember, entries[0].Tier)
	assert.Equal(t, []string{"result:approve"}, entries[1].Permissions)
	assert.Equal(t, domain.TierGuest, entries[2].Tier)
	assert.Empty(t, entries[3].Tier, "a role the catalogue does not know is shown without a tier")
	assert.NotNil(t, entries[3].Permissions)
	assert.Equal(t, 2, lookups, "each role is looked up once; platform roles not at all")
}

func TestUserService_AccessReport_AdminTierOnly(t *testing.T) {
	f := newUserFixture(&mockUserRepo{})
	for _, caller := range []*domain.Actor{nil, {ID: "U1", Role: domain.RoleUser, Tier: tierFor(domain.RoleUser), TenantID: "T1"}, {ID: "G", Role: domain.RoleGuest, Tier: domain.TierGuest}} {
		_, err := f.svc.AccessReport(context.Background(), caller)
		assert.EqualError(t, err, "unauthorized")
	}
}

func TestUserService_RecordLogin_StampsRepo(t *testing.T) {
	var id string
	var at time.Time
	f := newUserFixture(&mockUserRepo{RecordLoginFn: func(_ context.Context, i string, a time.Time) error { id, at = i, a; return nil }})

	require.NoError(t, f.svc.RecordLogin(context.Background(), "U1"))
	assert.Equal(t, "U1", id)
	assert.WithinDuration(t, time.Now(), at, time.Second)
}

func TestAuditService_Record_CarriesRequestMetaAndTenant(t *testing.T) {
	var saved *domain.AuditLog
	svc := NewAuditService(&mockAuditRepo{CreateFn: func(_ context.Context, l *domain.AuditLog) (*domain.AuditLog, error) {
		saved = l
		return l, nil
	}})
	ctx := domain.WithRequestMeta(context.Background(), domain.RequestMeta{IP: "203.0.113.9", UserAgent: "curl/8", RequestID: "req-1"})

	svc.Record(ctx, domain.AuditEntityUser, domain.AuditActionLoginSuccess, "U1", &domain.Actor{ID: "U1", TenantID: "T1"}, nil)

	require.NotNil(t, saved)
	assert.Equal(t, "203.0.113.9", saved.IP)
	assert.Equal(t, "curl/8", saved.UserAgent)
	assert.Equal(t, "req-1", saved.RequestID)
	assert.Equal(t, "T1", saved.TenantID)
}
