// Package bootstrap creates the first SUPER user and the hidden tenant it belongs to.
// The HTTP API cannot do this: register forces GUEST and needs a tenant to exist.
package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
)

// Actor is recorded on the audit rows and in users.created_by.
const Actor = "bootstrap"

// Password length rule, the same as the DTOs (CLAUDE.md: no strength policy yet).
const (
	minPassword = 4
	maxPassword = 20
)

// Result identifies what Run created.
type Result struct {
	TenantID string
	UserID   string
	Username string
}

// Run creates a hidden tenant named tenantName and a SUPER user in it, in one transaction.
// It refuses when any SUPER user already exists (even a soft-deleted one) or the username
// is taken, so it cannot be used later to add an unaudited SUPER.
func Run(ctx context.Context, db *sql.DB, hasher ports.PasswordHasher, tenantName, username, display, password string) (*Result, error) {
	tenantName = strings.TrimSpace(tenantName)
	username = strings.TrimSpace(username)
	if tenantName == "" {
		return nil, errors.New("tenant name is required")
	}
	if username == "" {
		return nil, errors.New("username is required")
	}
	if n := len([]rune(password)); n < minPassword || n > maxPassword {
		return nil, fmt.Errorf("password must be %d-%d characters", minPassword, maxPassword)
	}
	hash, err := hasher.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var supers int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'SUPER'`).Scan(&supers); err != nil {
		return nil, fmt.Errorf("check existing SUPER: %w", err)
	}
	if supers > 0 {
		return nil, errors.New("a SUPER user already exists; create further users through the API")
	}
	var taken bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)`, username).Scan(&taken); err != nil {
		return nil, fmt.Errorf("check username: %w", err)
	}
	if taken {
		return nil, fmt.Errorf("username %q is already taken", username)
	}
	var tenantTaken bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1 AND deleted_at IS NULL)`, tenantName).Scan(&tenantTaken); err != nil {
		return nil, fmt.Errorf("check tenant: %w", err)
	}
	if tenantTaken {
		return nil, fmt.Errorf("a tenant named %q already exists", tenantName)
	}

	res := &Result{TenantID: uuid.New().String(), UserID: uuid.New().String(), Username: username}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tenants (id, name, kind, hidden) VALUES ($1, $2, 'OTHER', true)`,
		res.TenantID, tenantName); err != nil {
		return nil, fmt.Errorf("insert tenant: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (id, tenant_id, username, password, status, role, display, created_by)
		 VALUES ($1, $2, $3, $4, true, 'SUPER', NULLIF($5, ''), $6)`,
		res.UserID, res.TenantID, username, hash, display, Actor); err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	if err := audit(ctx, tx, domain.AuditEntityTenant, res.TenantID, res.TenantID,
		`{"name":"`+jsonEscape(tenantName)+`","kind":"OTHER","hidden":true}`); err != nil {
		return nil, err
	}
	if err := audit(ctx, tx, domain.AuditEntityUser, res.UserID, res.TenantID,
		`{"username":"`+jsonEscape(username)+`","role":"SUPER"}`); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}

func audit(ctx context.Context, tx *sql.Tx, entity domain.AuditEntity, entityID, tenantID, changes string) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_logs (id, entity, entity_id, action, actor_name, changes, tenant_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		uuid.New().String(), string(entity), entityID, string(domain.AuditActionCreate), Actor, changes, tenantID); err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// jsonEscape escapes s for use inside a JSON string literal.
func jsonEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return r.Replace(s)
}
