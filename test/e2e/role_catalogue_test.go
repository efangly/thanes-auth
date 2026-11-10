//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestRoleCatalogue_LabRoleReachesTheToken walks ADR 0006 end to end: SUPER
// registers a LAB permission and a MEMBER-tier role granting it, a LAB admin
// gives that role to a user, and the user's token carries role, tier, kind and
// permissions. The role cannot be removed while the user holds it.
func TestRoleCatalogue_LabRoleReachesTheToken(t *testing.T) {
	root := adminToken(t)
	suffix := strings.ToUpper(strings.ReplaceAll(e2eName("r")[len("e2e-r-"):], "-", "_"))
	roleName := "E2E_APPROVER_" + suffix
	permission := "e2e:approve:" + strings.ToLower(suffix)

	resp, env := doJSON(t, http.MethodPost, "/permission", map[string]any{"kind": "LAB", "key": permission}, root)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create permission: status %d, message %q", resp.StatusCode, env.Message)
	}
	resp, env = doJSON(t, http.MethodPost, "/role", map[string]any{
		"kind": "LAB", "name": roleName, "tier": "MEMBER", "permissions": []string{permission},
	}, root)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create role: status %d, message %q", resp.StatusCode, env.Message)
	}

	lab := createTenant(t, root, "LAB")
	factory := createTenant(t, root, "FACTORY")
	admin := createAdmin(t, root, lab)
	adminLogin := loginAs(t, admin.Username, admin.Password)

	// The role exists only for LAB.
	resp, env = doJSON(t, http.MethodPost, "/user", map[string]any{
		"tenantId": factory, "username": e2eName("wrongkind"), "password": testPassword, "role": roleName,
	}, root)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("role of another kind: status %d (%q), want 400", resp.StatusCode, env.Message)
	}

	// A LAB admin reads its own kind's catalogue and nothing else.
	resp, _ = doJSON(t, http.MethodGet, "/role?kind=FACTORY", nil, adminLogin.Token)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin listing another kind: status %d, want 200 with an empty list", resp.StatusCode)
	}

	user := createUserWithRole(t, adminLogin.Token, lab, roleName)
	login := loginAs(t, user.Username, user.Password)
	claims := decodeJWTClaims(t, login.Token)
	if claims["role"] != roleName || claims["tier"] != "MEMBER" || claims["tenantKind"] != "LAB" {
		t.Errorf("claims = role %v tier %v tenantKind %v, want %s MEMBER LAB", claims["role"], claims["tier"], claims["tenantKind"], roleName)
	}
	perms, _ := claims["permissions"].([]any)
	if len(perms) != 1 || perms[0] != permission {
		t.Errorf("permissions claim = %v, want [%s]", claims["permissions"], permission)
	}

	resp, env = doJSON(t, http.MethodDelete, "/role/LAB/"+roleName, nil, root)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("remove a held role: status %d (%q), want 400", resp.StatusCode, env.Message)
	}
	resp, env = doJSON(t, http.MethodPost, "/role", map[string]any{"kind": "LAB", "name": "E2E_X_" + suffix, "tier": "MEMBER"}, adminLogin.Token)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("tenant admin changing the catalogue: status %d (%q), want 403", resp.StatusCode, env.Message)
	}
}
