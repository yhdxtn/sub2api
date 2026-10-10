package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	adminhandler "github.com/Wei-Shaw/sub2api/internal/handler/admin"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Only the identity reads needed by the real AdminAuth middleware are supplied.
// No database, imported account credentials or external service is involved.
type accountVaultSecurityUsers struct {
	service.UserRepository
	users map[int64]*service.User
}

func (r *accountVaultSecurityUsers) GetByID(_ context.Context, id int64) (*service.User, error) {
	user, ok := r.users[id]
	if !ok {
		return nil, service.ErrUserNotFound
	}
	copy := *user
	return &copy, nil
}

func (r *accountVaultSecurityUsers) GetUserAvatar(context.Context, int64) (*service.UserAvatar, error) {
	return nil, nil
}

func accountVaultSecurityUser(id int64, role string) *service.User {
	return &service.User{
		ID: id, Email: "synthetic-route-user@example.test", Role: role,
		Status: service.StatusActive, TokenVersion: 1, TokenVersionResolved: true,
	}
}

func newAccountVaultSecurityRouter(t *testing.T, stepUp servermiddleware.StepUpAuthMiddleware) (*gin.Engine, *service.AuthService, *accountVaultSecurityUsers) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	users := &accountVaultSecurityUsers{users: make(map[int64]*service.User)}
	cfg := &config.Config{JWT: config.JWTConfig{
		Secret: "synthetic-account-vault-route-test-signing-key", ExpireHour: 1,
	}}
	auth := service.NewAuthService(nil, users, nil, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	userService := service.NewUserService(users, nil, nil, nil)
	adminAuth := servermiddleware.NewAdminAuthMiddleware(auth, userService, nil, nil)
	if stepUp == nil {
		stepUp = servermiddleware.StepUpAuthMiddleware(func(c *gin.Context) { c.Next() })
	}
	vault := service.NewAccountVaultService(nil, nil)
	handlers := &handler.Handlers{Admin: &handler.AdminHandlers{
		AccountVault:         adminhandler.NewAccountVaultHandler(vault),
		AccountVaultRotation: adminhandler.NewAccountVaultRotationHandler(service.NewAccountVaultRotationService(nil, vault, users)),
	}}
	router := gin.New()
	// Exercise the actual parent registrar; this fails if the vault is moved
	// outside the authenticated admin group or accidentally left unregistered.
	RegisterAdminRoutes(router.Group("/api/v1"), handlers, adminAuth,
		servermiddleware.AuditLogMiddleware(func(c *gin.Context) { c.Next() }), stepUp, nil, nil)
	return router, auth, users
}

func accountVaultSecurityToken(t *testing.T, auth *service.AuthService, user *service.User) string {
	t.Helper()
	token, err := auth.GenerateToken(context.Background(), user)
	require.NoError(t, err)
	return "Bearer " + token
}

func TestAccountVaultRoutesRejectUnauthenticatedOrdinaryAndRevokedUsers(t *testing.T) {
	router, auth, users := newAccountVaultSecurityRouter(t, nil)
	normal := accountVaultSecurityUser(1, service.RoleUser)
	users.users[normal.ID] = normal
	demoted := accountVaultSecurityUser(2, service.RoleUser)
	users.users[demoted.ID] = demoted
	oldAdminClaims := *demoted
	oldAdminClaims.Role = service.RoleAdmin
	inactive := accountVaultSecurityUser(3, service.RoleAdmin)
	inactive.Status = "disabled"
	users.users[inactive.ID] = inactive
	revoked := accountVaultSecurityUser(4, service.RoleAdmin)
	revoked.TokenVersion = 2
	users.users[revoked.ID] = revoked
	oldVersionClaims := *revoked
	oldVersionClaims.TokenVersion = 1

	cases := []struct {
		name          string
		authorization string
		status        int
		reason        string
	}{
		{name: "unauthenticated", status: http.StatusUnauthorized, reason: "UNAUTHORIZED"},
		{name: "ordinary_user", authorization: accountVaultSecurityToken(t, auth, normal), status: http.StatusForbidden, reason: "FORBIDDEN"},
		{name: "demoted_admin_old_claims", authorization: accountVaultSecurityToken(t, auth, &oldAdminClaims), status: http.StatusForbidden, reason: "FORBIDDEN"},
		{name: "inactive_admin", authorization: accountVaultSecurityToken(t, auth, inactive), status: http.StatusUnauthorized, reason: "USER_INACTIVE"},
		{name: "revoked_admin_token", authorization: accountVaultSecurityToken(t, auth, &oldVersionClaims), status: http.StatusUnauthorized, reason: "TOKEN_REVOKED"},
		{name: "deleted_user", authorization: accountVaultSecurityToken(t, auth, accountVaultSecurityUser(99, service.RoleAdmin)), status: http.StatusUnauthorized, reason: "USER_NOT_FOUND"},
		{name: "invalid_token", authorization: "Bearer synthetic-invalid-token", status: http.StatusUnauthorized, reason: "INVALID_TOKEN"},
	}
	endpoints := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/account-vault/status"},
		{http.MethodGet, "/api/v1/admin/account-vault"},
		{http.MethodGet, "/api/v1/admin/account-vault/groups"},
		{http.MethodPost, "/api/v1/admin/account-vault/groups/assign"},
		{http.MethodPost, "/api/v1/admin/account-vault/import"},
		{http.MethodPost, "/api/v1/admin/account-vault/parse"},
		{http.MethodPost, "/api/v1/admin/account-vault/codes"},
		{http.MethodPost, "/api/v1/admin/account-vault/export-text"},
		{http.MethodPost, "/api/v1/admin/account-vault/17/password"},
		{http.MethodPost, "/api/v1/admin/account-vault/17/secret"},
		{http.MethodDelete, "/api/v1/admin/account-vault/17"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/queue"},
		{http.MethodPost, "/api/v1/admin/account-vault/session/queue"},
		{http.MethodPost, "/api/v1/admin/account-vault/session/jobs/query"},
		{http.MethodPost, "/api/v1/admin/account-vault/session/export"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/jobs/query"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/00000000-0000-4000-8000-000000000001/resume"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/00000000-0000-4000-8000-000000000001/cancel"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/worker-token"},
		{http.MethodDelete, "/api/v1/admin/account-vault/rotation/worker-token"},
	}
	for _, tc := range cases {
		for _, endpoint := range endpoints {
			t.Run(tc.name+"/"+endpoint.method+endpoint.path, func(t *testing.T) {
				request := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(`{}`))
				request.Header.Set("Content-Type", "application/json")
				if tc.authorization != "" {
					request.Header.Set("Authorization", tc.authorization)
				}
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				require.Equal(t, tc.status, response.Code)
				require.Contains(t, response.Body.String(), tc.reason)
			})
		}
	}
}

func TestAccountVaultRoutesOnlyRegisterInAdminNamespace(t *testing.T) {
	router, _, _ := newAccountVaultSecurityRouter(t, nil)
	var registered []string
	for _, route := range router.Routes() {
		if strings.Contains(route.Path, "account-vault") {
			registered = append(registered, route.Method+" "+route.Path)
		}
	}
	require.ElementsMatch(t, []string{
		"GET /api/v1/admin/account-vault/status",
		"GET /api/v1/admin/account-vault",
		"GET /api/v1/admin/account-vault/groups",
		"POST /api/v1/admin/account-vault/groups/assign",
		"POST /api/v1/admin/account-vault/import",
		"POST /api/v1/admin/account-vault/parse",
		"POST /api/v1/admin/account-vault/codes",
		"POST /api/v1/admin/account-vault/export-text",
		"POST /api/v1/admin/account-vault/:id/password",
		"POST /api/v1/admin/account-vault/:id/secret",
		"DELETE /api/v1/admin/account-vault/:id",
		"POST /api/v1/admin/account-vault/rotation/queue",
		"POST /api/v1/admin/account-vault/rotation/jobs/query",
		"POST /api/v1/admin/account-vault/session/queue",
		"POST /api/v1/admin/account-vault/session/jobs/query",
		"POST /api/v1/admin/account-vault/session/export",
		"POST /api/v1/admin/account-vault/rotation/:job/resume",
		"POST /api/v1/admin/account-vault/rotation/:job/cancel",
		"POST /api/v1/admin/account-vault/rotation/worker-token",
		"DELETE /api/v1/admin/account-vault/rotation/worker-token",
	}, registered)
}

func TestAccountVaultStatusAllowsRealAdminAndDisablesCaching(t *testing.T) {
	router, auth, users := newAccountVaultSecurityRouter(t, nil)
	admin := accountVaultSecurityUser(10, service.RoleAdmin)
	users.users[admin.ID] = admin
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/account-vault/status", nil)
	request.Header.Set("Authorization", accountVaultSecurityToken(t, auth, admin))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	var envelope struct {
		Code int                        `json:"code"`
		Data service.AccountVaultStatus `json:"data"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	require.Zero(t, envelope.Code)
	require.False(t, envelope.Data.Configured)
	require.False(t, envelope.Data.Ready)
	require.NotEmpty(t, envelope.Data.Message)
	require.Positive(t, envelope.Data.MaxImportRows)
	require.Equal(t, "no-store, private", response.Header().Get("Cache-Control"))
	require.Equal(t, "no-cache", response.Header().Get("Pragma"))
	require.Contains(t, response.Header().Get("Vary"), "Authorization")
	require.Equal(t, "nosniff", response.Header().Get("X-Content-Type-Options"))
}

func TestAccountVaultCredentialReadsKeepStepUpMiddleware(t *testing.T) {
	calls := 0
	stepUp := servermiddleware.StepUpAuthMiddleware(func(c *gin.Context) {
		calls++
		servermiddleware.AbortWithError(c, http.StatusForbidden, "STEP_UP_REQUIRED", "synthetic step-up test")
	})
	router, auth, users := newAccountVaultSecurityRouter(t, stepUp)
	admin := accountVaultSecurityUser(11, service.RoleAdmin)
	users.users[admin.ID] = admin
	authorization := accountVaultSecurityToken(t, auth, admin)
	for _, endpoint := range []string{"17/password", "17/secret", "export-text"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/account-vault/"+endpoint, nil)
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusForbidden, response.Code)
		require.Contains(t, response.Body.String(), "STEP_UP_REQUIRED")
		require.Equal(t, "no-store, private", response.Header().Get("Cache-Control"))
	}
	require.Equal(t, 3, calls)
}

func TestAccountVaultRotationWritesKeepStepUpMiddleware(t *testing.T) {
	calls := 0
	stepUp := servermiddleware.StepUpAuthMiddleware(func(c *gin.Context) {
		calls++
		servermiddleware.AbortWithError(c, http.StatusForbidden, "STEP_UP_REQUIRED", "synthetic step-up test")
	})
	router, auth, users := newAccountVaultSecurityRouter(t, stepUp)
	admin := accountVaultSecurityUser(12, service.RoleAdmin)
	users.users[admin.ID] = admin
	authorization := accountVaultSecurityToken(t, auth, admin)
	for _, endpoint := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/admin/account-vault/import"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/queue"},
		{http.MethodPost, "/api/v1/admin/account-vault/session/queue"},
		{http.MethodPost, "/api/v1/admin/account-vault/session/export"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/00000000-0000-4000-8000-000000000001/resume"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/00000000-0000-4000-8000-000000000001/cancel"},
		{http.MethodPost, "/api/v1/admin/account-vault/rotation/worker-token"},
		{http.MethodDelete, "/api/v1/admin/account-vault/rotation/worker-token"},
	} {
		request := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusForbidden, response.Code)
		require.Contains(t, response.Body.String(), "STEP_UP_REQUIRED")
		require.Equal(t, "no-store, private", response.Header().Get("Cache-Control"))
	}
	require.Equal(t, 8, calls)
}

func TestAccountVaultWorkerRoutesRequireSeparateCapabilityAndNeverCache(t *testing.T) {
	router, auth, users := newAccountVaultSecurityRouter(t, nil)
	admin := accountVaultSecurityUser(20, service.RoleAdmin)
	ordinary := accountVaultSecurityUser(21, service.RoleUser)
	users.users[admin.ID], users.users[ordinary.ID] = admin, ordinary
	vault := service.NewAccountVaultService(nil, nil)
	handlers := &handler.Handlers{Admin: &handler.AdminHandlers{
		AccountVaultRotation: adminhandler.NewAccountVaultRotationHandler(service.NewAccountVaultRotationService(nil, vault, users)),
	}}
	RegisterAccountVaultWorkerRoutes(router.Group("/api/v1"), handlers)
	var registered []string
	for _, route := range router.Routes() {
		if strings.Contains(route.Path, "/account-vault-worker") {
			registered = append(registered, route.Method+" "+route.Path)
		}
	}
	require.ElementsMatch(t, []string{
		"POST /api/v1/account-vault-worker/claim",
		"POST /api/v1/account-vault-worker/:job/heartbeat",
		"POST /api/v1/account-vault-worker/:job/checkpoint",
		"POST /api/v1/account-vault-worker/:job/login-code",
		"POST /api/v1/account-vault-worker/:job/activation-code",
		"POST /api/v1/account-vault-worker/:job/pause",
		"POST /api/v1/account-vault-worker/:job/session/save",
		"POST /api/v1/account-vault-worker/:job/session/authorize",
		"POST /api/v1/account-vault-worker/:job/session/complete",
	}, registered)
	for _, tc := range []struct {
		name, authorization, apiKey, query string
	}{
		{name: "missing"},
		{name: "admin JWT", authorization: accountVaultSecurityToken(t, auth, admin)},
		{name: "ordinary JWT", authorization: accountVaultSecurityToken(t, auth, ordinary)},
		{name: "unknown capability", authorization: "Bearer avw1_" + strings.Repeat("a", 43)},
		{name: "global API key", apiKey: "synthetic-admin-api-key"},
		{name: "query token ignored", query: "?token=avw1_" + strings.Repeat("a", 43)},
	} {
		for _, endpoint := range []string{"claim", "00000000-0000-4000-8000-000000000001/heartbeat", "00000000-0000-4000-8000-000000000001/checkpoint", "00000000-0000-4000-8000-000000000001/login-code", "00000000-0000-4000-8000-000000000001/activation-code", "00000000-0000-4000-8000-000000000001/pause", "00000000-0000-4000-8000-000000000001/session/authorize", "00000000-0000-4000-8000-000000000001/session/save", "00000000-0000-4000-8000-000000000001/session/complete"} {
			t.Run(tc.name+"/"+endpoint, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodPost, "/api/v1/account-vault-worker/"+endpoint+tc.query, strings.NewReader(`{}`))
				request.Header.Set("Authorization", tc.authorization)
				request.Header.Set("x-api-key", tc.apiKey)
				writer := httptest.NewRecorder()
				router.ServeHTTP(writer, request)
				require.Equal(t, http.StatusUnauthorized, writer.Code)
				require.Contains(t, writer.Body.String(), "ACCOUNT_VAULT_WORKER_UNAUTHORIZED")
				require.Equal(t, "no-store, private", writer.Header().Get("Cache-Control"))
				require.Equal(t, "no-cache", writer.Header().Get("Pragma"))
				require.Contains(t, writer.Header().Get("Vary"), "Authorization")
				require.NotContains(t, writer.Body.String(), "synthetic-admin-api-key")
			})
		}
	}
}
