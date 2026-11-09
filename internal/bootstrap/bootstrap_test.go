package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noHasher struct{}

func (noHasher) Hash(string) (string, error) { return "h", nil }
func (noHasher) Compare(string, string) bool { return false }
func (noHasher) CompareDummy(string)         {}

func TestRun_RejectsBadInputBeforeTouchingTheDatabase(t *testing.T) {
	tests := []struct {
		name, tenant, user, password, want string
	}{
		{"no tenant", " ", "root", "secret", "tenant name"},
		{"no username", "siamatic", "", "secret", "username"},
		{"short password", "siamatic", "root", "abc", "password must be"},
		{"long password", "siamatic", "root", "123456789012345678901", "password must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A nil db would panic if validation let the call through.
			_, err := Run(context.Background(), nil, noHasher{}, tt.tenant, tt.user, "", tt.password)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestJSONEscape(t *testing.T) {
	assert.Equal(t, `a\"b\\c`, jsonEscape(`a"b\c`))
}
