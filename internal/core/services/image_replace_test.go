package services

import (
	"context"
	"errors"
	"testing"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordUploads makes the mock upload hand out newURL and note every delete
// as "<folder>/<name>".
func recordUploads(m *mockUpload, newURL string) *[]string {
	var deleted []string
	m.UploadFn = func(*domain.File, string) (string, error) { return newURL, nil }
	m.DeleteFn = func(folder, name string) error { deleted = append(deleted, folder+"/"+name); return nil }
	return &deleted
}

const (
	oldPic = "http://host/auth/image/user/old.png"
	newPic = "http://host/auth/image/user/new.png"
)

func userWithPic(role domain.Role) func(context.Context, string) (*domain.User, error) {
	return func(_ context.Context, id string) (*domain.User, error) {
		pic := oldPic
		return &domain.User{ID: id, Username: "user1", Role: role, TenantID: "T1", Pic: &pic}, nil
	}
}

func TestUserService_Update_Picture_OldRemovedOnlyAfterSave(t *testing.T) {
	repo := &mockUserRepo{
		FindByIDFn: userWithPic(domain.RoleUser),
		UpdateFn: func(_ context.Context, _ string, p domain.UserPatch) (*domain.User, error) {
			return &domain.User{ID: "U1", Pic: p.Pic}, nil
		},
	}
	svc, _, upload := newTestUserService(repo)
	deleted := recordUploads(upload, newPic)

	user, err := svc.Update(context.Background(), "U1", domain.UserPatch{}, &domain.File{Name: "p.png"}, superCaller)
	require.NoError(t, err)
	assert.Equal(t, newPic, *user.Pic)
	assert.Equal(t, []string{"user/old.png"}, *deleted)
}

func TestUserService_Update_Picture_SaveFails_NewRemovedOldKept(t *testing.T) {
	repo := &mockUserRepo{
		FindByIDFn: userWithPic(domain.RoleUser),
		UpdateFn: func(context.Context, string, domain.UserPatch) (*domain.User, error) {
			return nil, errors.New("update failed")
		},
	}
	svc, _, upload := newTestUserService(repo)
	deleted := recordUploads(upload, newPic)

	_, err := svc.Update(context.Background(), "U1", domain.UserPatch{}, &domain.File{Name: "p.png"}, superCaller)
	assert.EqualError(t, err, "update failed")
	assert.Equal(t, []string{"user/new.png"}, *deleted, "the record still points at old.png, so only the new file goes")
}

func TestUserService_Update_Picture_HashFails_NewRemoved(t *testing.T) {
	f := newUserFixture(&mockUserRepo{FindByIDFn: userWithPic(domain.RoleUser)})
	deleted := recordUploads(f.upload, newPic)

	_, err := f.svc.Update(context.Background(), "U1", domain.UserPatch{Password: ptr("")}, &domain.File{Name: "p.png"}, superCaller)
	assert.EqualError(t, err, "invalid password")
	assert.Equal(t, []string{"user/new.png"}, *deleted)
}

func TestUserService_Update_NoFile_DeletesNothing(t *testing.T) {
	repo := &mockUserRepo{
		FindByIDFn: userWithPic(domain.RoleUser),
		UpdateFn: func(context.Context, string, domain.UserPatch) (*domain.User, error) {
			return &domain.User{ID: "U1"}, nil
		},
	}
	svc, _, upload := newTestUserService(repo)
	deleted := recordUploads(upload, newPic)

	_, err := svc.Update(context.Background(), "U1", domain.UserPatch{Display: ptr("x")}, nil, superCaller)
	require.NoError(t, err)
	assert.Empty(t, *deleted)
}

func tenantWithPic(_ context.Context, id string) (*domain.Tenant, error) {
	pic := "http://host/auth/image/tenant/old.png"
	return &domain.Tenant{ID: id, Name: "T", Pic: &pic}, nil
}

func TestTenantService_Update_Picture_OldRemovedOnlyAfterSave(t *testing.T) {
	repo := &mockTenantRepo{
		FindByIDFn: tenantWithPic,
		UpdateFn: func(_ context.Context, id string, p domain.TenantPatch) (*domain.Tenant, error) {
			return &domain.Tenant{ID: id, Name: "T", Pic: p.Pic}, nil
		},
	}
	svc, _, upload, _ := newTestTenantService(repo)
	deleted := recordUploads(upload, "http://host/auth/image/tenant/new.png")

	_, err := svc.Update(context.Background(), "T1", domain.TenantPatch{}, &domain.File{Name: "p.png"}, superCaller)
	require.NoError(t, err)
	assert.Equal(t, []string{"tenant/old.png"}, *deleted)
}

func TestTenantService_Update_Picture_SaveFails_NewRemovedOldKept(t *testing.T) {
	repo := &mockTenantRepo{
		FindByIDFn: tenantWithPic,
		UpdateFn: func(context.Context, string, domain.TenantPatch) (*domain.Tenant, error) {
			return nil, errors.New("db down")
		},
	}
	svc, _, upload, _ := newTestTenantService(repo)
	deleted := recordUploads(upload, "http://host/auth/image/tenant/new.png")

	_, err := svc.Update(context.Background(), "T1", domain.TenantPatch{}, &domain.File{Name: "p.png"}, superCaller)
	assert.EqualError(t, err, "db down")
	assert.Equal(t, []string{"tenant/new.png"}, *deleted)
}
