package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func accountVaultAuditActor(c *gin.Context) {
	c.Set(string(ContextKeyUser), AuthSubject{UserID: 77})
	c.Set(string(ContextKeyUserRole), service.RoleAdmin)
	c.Set(ContextKeyAuthEmail, "synthetic-admin@example.test")
	c.Set("auth_method", service.AuditAuthMethodJWT)
	c.Next()
}

func TestAccountVaultAuditOmitsImportAndParsedQRBodies(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		action string
		body   string
		status int
	}{
		{"text_import", "/api/v1/admin/account-vault/import", "admin.account_vault.import", `{"content":"synthetic@example.test----vault-audit-password-canary----vault-audit-seed-canary"}`, http.StatusOK},
		{"structured_import", "/api/v1/admin/account-vault/import", "admin.account_vault.import", `{"items":[{"email":"synthetic@example.test","password":"vault-audit-password-canary","secret":"vault-audit-seed-canary"}]}`, http.StatusOK},
		{"failed_import", "/api/v1/admin/account-vault/import", "admin.account_vault.import", `{"content":"vault-audit-password-canary", "malformed":`, http.StatusBadRequest},
		{"qr_parse", "/api/v1/admin/account-vault/parse", "admin.account_vault.parse", `{"uri":"otpauth://totp/Synthetic:synthetic@example.test?secret=vault-audit-seed-canary"}`, http.StatusOK},
		{"failed_qr_parse", "/api/v1/admin/account-vault/parse", "admin.account_vault.parse", `{"uri":"vault-audit-password-canary----vault-audit-seed-canary"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			repository := &auditCaptureRepository{}
			auditService := service.NewAuditLogService(repository, nil)
			auditService.Start()
			t.Cleanup(auditService.Stop)
			router := gin.New()
			router.Use(accountVaultAuditActor, gin.HandlerFunc(NewAuditLogMiddleware(auditService)))
			router.POST(tc.path, func(c *gin.Context) {
				// Omitting the audit copy must preserve the original request for
				// validation and import. Test canaries are not usable credentials.
				body, err := io.ReadAll(c.Request.Body)
				require.NoError(t, err)
				require.Equal(t, tc.body, string(body))
				SetAuditExtra(c, map[string]any{
					"requested_count": 1,
					"secret":          "vault-audit-extra-canary",
					"content":         tc.body,
				})
				c.JSON(tc.status, gin.H{"secret": "vault-audit-response-canary"})
			})
			request := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, tc.status, response.Code)
			auditService.Stop()

			repository.mu.Lock()
			logs := append([]*service.AuditLog(nil), repository.logs...)
			repository.mu.Unlock()
			require.Len(t, logs, 1)
			entry := logs[0]
			require.Equal(t, tc.action, entry.Action)
			require.Equal(t, tc.status, entry.StatusCode)
			require.Equal(t, "<credential-bearing body omitted>", entry.RequestBody)
			require.NotNil(t, entry.ActorUserID)
			require.EqualValues(t, 77, *entry.ActorUserID)
			require.Equal(t, service.RoleAdmin, entry.ActorRole)
			require.EqualValues(t, 1, entry.Extra["requested_count"])
			encoded, err := json.Marshal(entry)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), "vault-audit-")
		})
	}
}

func TestAccountVaultAuditRecordsSensitiveOperationsWithoutResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repository := &auditCaptureRepository{}
	auditService := service.NewAuditLogService(repository, nil)
	auditService.Start()
	t.Cleanup(auditService.Stop)
	router := gin.New()
	router.Use(accountVaultAuditActor, gin.HandlerFunc(NewAuditLogMiddleware(auditService)))
	operations := []struct {
		method  string
		pattern string
		path    string
		action  string
		body    string
	}{
		{http.MethodGet, "/api/v1/admin/account-vault", "/api/v1/admin/account-vault?page=1", "admin.account_vault.list", ""},
		{http.MethodPost, "/api/v1/admin/account-vault/codes", "/api/v1/admin/account-vault/codes", "admin.account_vault.codes", `{"ids":[17,18]}`},
		{http.MethodPost, "/api/v1/admin/account-vault/:id/password", "/api/v1/admin/account-vault/17/password", "admin.account_vault.password.read", `{}`},
		{http.MethodPost, "/api/v1/admin/account-vault/:id/secret", "/api/v1/admin/account-vault/17/secret", "admin.account_vault.secret.read", `{}`},
		{http.MethodDelete, "/api/v1/admin/account-vault/:id", "/api/v1/admin/account-vault/17", "admin.account_vault.delete", ""},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/queue", "/api/v1/admin/account-vault/rotation/queue", "admin.account_vault.rotation.queue", `{"ids":[17]}`},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/worker-token", "/api/v1/admin/account-vault/rotation/worker-token", "admin.account_vault.rotation.worker_token.create", `{}`},
		{http.MethodDelete, "/api/v1/admin/account-vault/rotation/worker-token", "/api/v1/admin/account-vault/rotation/worker-token", "admin.account_vault.rotation.worker_token.revoke", ""},
	}
	for _, operation := range operations {
		router.Handle(operation.method, operation.pattern, func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"password": "vault-audit-response-password-canary",
				"secret":   "vault-audit-response-seed-canary",
				"code":     "vault-audit-response-code-canary",
				"token":    "vault-audit-response-worker-ticket-canary",
			})
		})
	}
	for _, operation := range operations {
		request := httptest.NewRequest(operation.method, operation.path, strings.NewReader(operation.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code)
	}
	auditService.Stop()

	repository.mu.Lock()
	logs := append([]*service.AuditLog(nil), repository.logs...)
	repository.mu.Unlock()
	require.Len(t, logs, len(operations))
	byAction := make(map[string]*service.AuditLog, len(logs))
	for _, entry := range logs {
		byAction[entry.Action] = entry
		require.NotNil(t, entry.ActorUserID)
		require.EqualValues(t, 77, *entry.ActorUserID)
		require.Equal(t, http.StatusOK, entry.StatusCode)
		encoded, err := json.Marshal(entry)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "vault-audit-response-")
	}
	for _, operation := range operations {
		entry, present := byAction[operation.action]
		require.Truef(t, present, "sensitive operation %s must produce an audit entry", operation.action)
		if present {
			require.Equal(t, operation.pattern, entry.Path)
		}
	}
	require.JSONEq(t, `{"ids":[17,18]}`, byAction["admin.account_vault.codes"].RequestBody)
}
