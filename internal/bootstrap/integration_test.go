//go:build integration

package bootstrap

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efangly/smtrack-authentication/internal/adapters/driven/database"
)

func TestRun(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", url)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, database.Migrate(ctx, db))
	// audit_logs cannot be cleaned up, so the test needs a database without a SUPER user.
	var supers int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'SUPER'`).Scan(&supers))
	require.Zero(t, supers, "TEST_DATABASE_URL must point at a database without a SUPER user")

	res, err := Run(ctx, db, noHasher{}, "boot-tenant", "boot-root", "Root", "secret")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, res.UserID)
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, res.TenantID)
	})

	var hidden bool
	var role string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT hidden FROM tenants WHERE id = $1`, res.TenantID).Scan(&hidden))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT role FROM users WHERE id = $1`, res.UserID).Scan(&role))
	assert.True(t, hidden)
	assert.Equal(t, "SUPER", role)

	var audits int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE actor_name = $1 AND tenant_id = $2`, Actor, res.TenantID).Scan(&audits))
	assert.Equal(t, 2, audits)

	_, err = Run(ctx, db, noHasher{}, "other", "boot-other", "", "secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SUPER user already exists")
}
