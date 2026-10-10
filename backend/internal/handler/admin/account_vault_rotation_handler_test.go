package admin

import (
	"bytes"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountVaultRotationStrictNestedJSON(t *testing.T) {
	const valid = `{"lease_token":"synthetic-lease","revision":2,"action":"enrolled","enrollment":{"secret":"synthetic-canary","session_id":"synthetic-session","factor_id":"synthetic-factor","factor_type":"totp"}}`
	inputs := map[string]string{"valid": valid, "duplicate_secret": strings.Replace(valid, `"secret":"synthetic-canary"`, `"secret":"synthetic-canary","secret":"overwrite"`, 1), "uppercase_secret": strings.Replace(valid, `"secret":`, `"Secret":`, 1), "unknown_nested": strings.Replace(valid, `"factor_type":"totp"`, `"factor_type":"totp","extra":"x"`, 1), "null_secret": strings.Replace(valid, `"secret":"synthetic-canary"`, `"secret":null`, 1), "null_enrollment": `{"lease_token":"x","revision":2,"action":"enrolled","enrollment":null}`, "missing_session": strings.Replace(valid, `"session_id":"synthetic-session",`, ``, 1), "duplicate_top": strings.Replace(valid, `"revision":2`, `"revision":2,"revision":3`, 1), "missing_false_boolean": `{"lease_token":"x","revision":2,"action":"disabled","identity":{"id":"synthetic","email":"a@example.test"},"mfa":{"enabled":false,"default_factor_id":"","totp_factor_ids":[]}}`, "false_booleans_valid": `{"lease_token":"x","revision":2,"action":"disabled","identity":{"id":"synthetic","email":"a@example.test"},"mfa":{"enabled":false,"enabled_v2":false,"default_factor_id":"","totp_factor_ids":[]}}`, "extra_json_value": valid + ` {}`}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/rotation", bytes.NewBufferString(input))
			var req service.AccountVaultRotationCheckpoint
			ok := bindRotationJSON(c, &req)
			if name == "valid" || name == "false_booleans_valid" {
				require.True(t, ok)
			} else {
				require.False(t, ok)
				require.Equal(t, 400, w.Code)
				require.NotContains(t, w.Body.String(), "synthetic-canary")
				require.NotContains(t, w.Body.String(), "overwrite")
			}
		})
	}
}
func TestAccountVaultRotationWorkerRejectsGlobalAdminKey(t *testing.T) {
	for _, header := range []string{"", "Bearer gateway-key", "bearer avw1_" + strings.Repeat("x", 43), "Bearer " + strings.Repeat("sensitive-canary", 20)} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/api/v1/account-vault-worker/claim", strings.NewReader(`{"worker_id":"test"}`))
		c.Request.Header.Set("Authorization", header)
		c.Request.Header.Set("x-api-key", "synthetic-admin-key")
		h := NewAccountVaultRotationHandler(nil)
		h.WorkerClaim(c)
		require.Equal(t, 401, w.Code)
		require.NotContains(t, w.Body.String(), "sensitive-canary")
		require.NotContains(t, w.Body.String(), "synthetic-admin-key")
	}
}
