package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTiersApp(allowed ...domain.Tier) *fiber.App {
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		// Simulate JWT auth middleware having run
		tokenStr := c.Get("X-Test-Token")
		if tokenStr != "" {
			if actor, err := testIssuer().VerifyAccess(tokenStr); err == nil {
				c.Locals("user", actor)
			}
		}
		return c.Next()
	})
	app.Get("/protected", TiersGuard(allowed...), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})
	return app
}

func TestTiersGuard_AllowedTier(t *testing.T) {
	app := setupTiersApp(domain.TierAdmin, domain.TierSuper)

	claims := jwt.MapClaims{
		"id":   "U1",
		"role": "LAB_HEAD",
		"tier": "ADMIN",
		"exp":  float64(time.Now().Add(1 * time.Hour).Unix()),
	}
	token := createTestToken(testJWTSecret, claims)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Test-Token", token)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTiersGuard_ForbiddenTierWhateverTheRole(t *testing.T) {
	app := setupTiersApp(domain.TierSuper) // Only SUPER allowed

	claims := jwt.MapClaims{
		"id":   "U1",
		"role": "SUPER",
		"tier": "MEMBER",
		"exp":  float64(time.Now().Add(1 * time.Hour).Unix()),
	}
	token := createTestToken(testJWTSecret, claims)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Test-Token", token)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestTiersGuard_NoUser(t *testing.T) {
	app := setupTiersApp(domain.TierAdmin)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	// No X-Test-Token header → no user in Locals
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestTiersGuard_NoTiersSpecified(t *testing.T) {
	// When no tiers are specified, all authenticated users pass
	app := setupTiersApp() // empty tiers

	claims := jwt.MapClaims{
		"id":   "U1",
		"role": "GUEST",
		"tier": "GUEST",
		"exp":  float64(time.Now().Add(1 * time.Hour).Unix()),
	}
	token := createTestToken(testJWTSecret, claims)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Test-Token", token)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
