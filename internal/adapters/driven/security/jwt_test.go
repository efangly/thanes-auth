package security

import (
	"errors"
	"testing"
	"time"

	"github.com/efangly/smtrack-authentication/config"
	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	accessSecret  = "test-access-secret"
	refreshSecret = "test-refresh-secret"
)

var testActor = domain.Actor{
	ID: "U1", Name: "Admin", Role: "LAB_HEAD", Tier: domain.TierAdmin, TenantID: "T1", TenantKind: domain.TenantKindLab,
	DepartmentIDs: []string{"D1", "D2"}, Permissions: []string{"result:approve", "result:view"},
}

func newTestIssuer() *jwtIssuer {
	return NewJWTIssuer(&config.Config{
		JWTSecret:         accessSecret,
		JWTRefreshSecret:  refreshSecret,
		ExpireTime:        "1h",
		RefreshExpireTime: "7d",
	}).(*jwtIssuer)
}

func sign(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func TestJWTIssuer_RoundTrip(t *testing.T) {
	j := newTestIssuer()
	pair, err := j.IssuePair(testActor)
	require.NoError(t, err)

	actor, err := j.VerifyAccess(pair.Access)
	require.NoError(t, err)
	assert.Equal(t, testActor, *actor)

	claims, err := j.VerifyRefresh(pair.Refresh)
	require.NoError(t, err)
	assert.Equal(t, "U1", claims.UserID)
	assert.NotEmpty(t, claims.TokenID)
	assert.True(t, claims.ExpiresAt.After(claims.IssuedAt))
}

func TestJWTIssuer_ClaimsAndLifetimes(t *testing.T) {
	j := newTestIssuer()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }

	pair, err := j.IssuePair(testActor)
	require.NoError(t, err)

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(pair.Access, claims, func(*jwt.Token) (any, error) { return []byte(accessSecret), nil },
		jwt.WithTimeFunc(func() time.Time { return now }))
	require.NoError(t, err)
	assert.Equal(t, "access", claims["typ"])
	assert.Equal(t, "LAB_HEAD", claims["role"])
	assert.Equal(t, "ADMIN", claims["tier"])
	assert.Equal(t, "T1", claims["tenantId"])
	assert.Equal(t, "LAB", claims["tenantKind"])
	assert.Equal(t, []any{"result:approve", "result:view"}, claims["permissions"])
	assert.Equal(t, []any{"D1", "D2"}, claims["departmentIds"])
	assert.EqualValues(t, now.Add(time.Hour).Unix(), claims["exp"])

	claims = jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(pair.Refresh, claims, func(*jwt.Token) (any, error) { return []byte(refreshSecret), nil },
		jwt.WithTimeFunc(func() time.Time { return now }))
	require.NoError(t, err)
	assert.Equal(t, "refresh", claims["typ"])
	assert.EqualValues(t, now.Add(7*24*time.Hour).Unix(), claims["exp"])
}

// The two token kinds must never stand in for each other — even if an
// operator configures the same secret for both.
func TestJWTIssuer_TokenTypesAreNotInterchangeable(t *testing.T) {
	j := NewJWTIssuer(&config.Config{JWTSecret: "same", JWTRefreshSecret: "same"})
	pair, err := j.IssuePair(testActor)
	require.NoError(t, err)

	_, err = j.VerifyAccess(pair.Refresh)
	assert.Error(t, err, "refresh token accepted as access token")
	_, err = j.VerifyRefresh(pair.Access)
	assert.Error(t, err, "access token accepted as refresh token")
}

func TestJWTIssuer_VerifyAccessReturnsTenantAndDepartments(t *testing.T) {
	j := newTestIssuer()
	pair, err := j.IssuePair(testActor)
	require.NoError(t, err)

	actor, err := j.VerifyAccess(pair.Access)
	require.NoError(t, err)
	assert.Equal(t, testActor, *actor)
}

// Authorization is by tier, so an access token without a valid one — issued
// before tiers existed, or crafted — is not honoured; refresh rebuilds it.
func TestJWTIssuer_AccessTokenWithoutTierIsRejected(t *testing.T) {
	j := newTestIssuer()
	exp := time.Now().Add(time.Hour).Unix()
	for _, tier := range []any{nil, "", "ROOT"} {
		claims := jwt.MapClaims{"id": "U1", "role": "SUPER", "typ": "access", "exp": exp}
		if tier != nil {
			claims["tier"] = tier
		}
		_, err := j.VerifyAccess(sign(t, accessSecret, claims))
		assert.Error(t, err, "tier %v", tier)
	}
}

func TestJWTIssuer_EmptyPermissionsAreAList(t *testing.T) {
	j := newTestIssuer()
	pair, err := j.IssuePair(domain.Actor{ID: "U1", Role: domain.RoleGuest, Tier: domain.TierGuest})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(pair.Access, claims, func(*jwt.Token) (any, error) { return []byte(accessSecret), nil })
	require.NoError(t, err)
	assert.Equal(t, []any{}, claims["permissions"], "downstream systems can rely on a list")
}

func TestJWTIssuer_TokenWithoutTypIsRejected(t *testing.T) {
	j := newTestIssuer()
	exp := time.Now().Add(time.Hour).Unix()
	untyped := jwt.MapClaims{"id": "U1", "role": "ADMIN", "tenantId": "T1", "exp": exp}

	_, err := j.VerifyAccess(sign(t, accessSecret, untyped))
	assert.Error(t, err)
	_, err = j.VerifyRefresh(sign(t, refreshSecret, untyped))
	assert.Error(t, err)
}

func TestJWTIssuer_Rejects(t *testing.T) {
	j := newTestIssuer()
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()

	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"id": "U1", "exp": future}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
	}{
		{"garbage", "not-a-jwt"},
		{"expired", sign(t, accessSecret, jwt.MapClaims{"id": "U1", "exp": past})},
		{"wrong secret", sign(t, "other-secret", jwt.MapClaims{"id": "U1", "exp": future})},
		{"refresh secret", sign(t, refreshSecret, jwt.MapClaims{"id": "U1", "exp": future})},
		{"alg none", none},
		{"wrong typ", sign(t, accessSecret, jwt.MapClaims{"id": "U1", "typ": "refresh", "exp": future})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := j.VerifyAccess(tt.token)
			assert.EqualError(t, err, "invalid or expired token")
			assert.Nil(t, errors.Unwrap(err), "must be a domain error so the client sees it")
		})
	}
}

func TestJWTIssuer_RefreshWithoutUserID(t *testing.T) {
	j := newTestIssuer()
	token := sign(t, refreshSecret, jwt.MapClaims{"typ": "refresh", "exp": time.Now().Add(time.Hour).Unix()})
	_, err := j.VerifyRefresh(token)
	assert.EqualError(t, err, "invalid or expired refresh token")
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
		{"7d", 7 * 24 * time.Hour},
		{"", time.Hour},
		{"invalid", time.Hour},
		{"0d", time.Hour},
		{"xd", time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, parseDuration(tt.input, time.Hour))
		})
	}
}
