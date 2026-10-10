package admin

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestVaultOAuthExchangeDiagnosticsDoNotExposeUpstreamSecrets(t *testing.T) {
	require.Equal(t, "exchange_failed", vaultOAuthExchangeFailureCode(errors.New("Bearer synthetic-secret callback?code=synthetic-code")))
	require.Equal(t, "invalid_grant", vaultOAuthExchangeFailureCode(errors.New(`{"error":"invalid_grant","refresh_token":"synthetic-secret"}`)))
	require.Equal(t, "unsupported_country_region_territory", vaultOAuthExchangeFailureCode(errors.New(`{"error":{"code":"unsupported_country_region_territory"}}`)))
}

func TestVaultSessionConversionUsesRealTokenExpiryAndRejectsWrongIdentity(t *testing.T) {
	token := buildCodexImportTestJWT(t, time.Now().Add(time.Hour), map[string]any{
		"sub": "auth0|user", "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace", "chatgpt_user_id": "user"},
	})
	value := map[string]any{"accessToken": token, "sessionToken": "synthetic-session-canary", "user": map[string]any{"id": "user", "email": "test@example.test"}, "account": map[string]any{"id": "workspace", "planType": "plus"}, "expires": time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)}
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	converted, err := normalizeVaultSession(raw, "test@example.test")
	require.NoError(t, err)
	var payload DataPayload
	require.NoError(t, json.Unmarshal(converted, &payload))
	require.Len(t, payload.Accounts, 1)
	account := payload.Accounts[0]
	require.Equal(t, "openai", account.Platform)
	require.Equal(t, "oauth", account.Type)
	require.Equal(t, token, account.Credentials["access_token"])
	require.Equal(t, "workspace", account.Credentials["chatgpt_account_id"])
	require.NotContains(t, string(converted), "synthetic-session-canary")
	require.InDelta(t, time.Now().Add(time.Hour).Unix(), *account.ExpiresAt, 2)
	_, err = normalizeVaultSession(raw, "other@example.test")
	require.Error(t, err)
	value["user"] = map[string]any{"id": "wrong-user", "email": "test@example.test"}
	raw, _ = json.Marshal(value)
	_, err = normalizeVaultSession(raw, "test@example.test")
	require.Error(t, err)
	value["user"] = map[string]any{"id": "user", "email": "test@example.test"}
	value["account"] = map[string]any{"id": "wrong-workspace"}
	raw, _ = json.Marshal(value)
	_, err = normalizeVaultSession(raw, "test@example.test")
	require.Error(t, err)
	value["account"] = map[string]any{"id": "workspace"}
	value["accessToken"] = buildCodexAccessToken(t, "workspace", "user", time.Now().Add(-time.Hour))
	raw, _ = json.Marshal(value)
	_, err = normalizeVaultSession(raw, "test@example.test")
	require.Error(t, err)
}

type vaultOAuthRecoveryAdmin struct {
	*codexImportMemoryAdminService
	cleared int
}

func (s *vaultOAuthRecoveryAdmin) ClearAccountError(_ context.Context, id int64) (*service.Account, error) {
	s.cleared++
	for i := range s.accounts {
		if s.accounts[i].ID == id {
			s.accounts[i].Status = service.StatusActive
			s.accounts[i].ErrorMessage = ""
			return &s.accounts[i], nil
		}
	}
	return nil, service.ErrVaultRotationInvalid
}

func TestVaultOAuthReauthorizationUpdatesSameAccountAndRecoversCredentialError(t *testing.T) {
	for _, status := range []string{service.StatusError, "disabled"} {
		t.Run(status, func(t *testing.T) {
			email := "test@example.test"
			token := buildCodexImportTestJWT(t, time.Now().Add(10*24*time.Hour), map[string]any{
				"client_id": openai.ClientID, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace", "chatgpt_user_id": "user"},
			})
			credentials := map[string]any{"access_token": token, "refresh_token": "synthetic-new-refresh", "id_token": "synthetic-id", "client_id": openai.ClientID, "email": email, "chatgpt_user_id": "user", "chatgpt_account_id": "workspace"}
			raw, err := normalizeVaultOAuthAuthorization(email, credentials)
			require.NoError(t, err)
			svc := &vaultOAuthRecoveryAdmin{codexImportMemoryAdminService: newCodexImportMemoryAdminService([]service.Account{{ID: 42, Name: email, Platform: "openai", Type: "oauth", Status: status, Concurrency: 7, Priority: 9, GroupIDs: []int64{23}, Credentials: map[string]any{"email": email, "chatgpt_account_id": "workspace", "chatgpt_user_id": "user", "refresh_token": "synthetic-old-refresh", "model_mapping": map[string]any{"alias": "model"}}, Extra: map[string]any{"base_rpm": float64(30)}}})}
			h := &AccountVaultRotationHandler{accounts: &AccountHandler{adminService: svc}}
			id, _, err := h.importVaultSession(context.Background(), raw, email)
			require.NoError(t, err)
			require.Equal(t, int64(42), id)
			require.Empty(t, svc.createdAccounts)
			require.Len(t, svc.updatedAccounts, 1)
			require.Equal(t, "synthetic-new-refresh", svc.accounts[0].Credentials["refresh_token"])
			require.Equal(t, map[string]any{"alias": "model"}, svc.accounts[0].Credentials["model_mapping"])
			require.Equal(t, []int64{23}, svc.accounts[0].GroupIDs)
			require.Equal(t, 7, svc.accounts[0].Concurrency)
			require.Equal(t, float64(30), svc.accounts[0].Extra["base_rpm"])
			require.Nil(t, svc.updatedAccounts[0].input.ExpiresAt)
			if status == service.StatusError {
				require.Equal(t, 1, svc.cleared)
				require.Equal(t, service.StatusActive, svc.accounts[0].Status)
			} else {
				require.Equal(t, 0, svc.cleared)
				require.Equal(t, "disabled", svc.accounts[0].Status)
			}
		})
	}
}

func TestVaultOAuthImportRejectsWebTokenAndDifferentAccount(t *testing.T) {
	email := "test@example.test"
	web := buildCodexImportTestJWT(t, time.Now().Add(time.Hour), map[string]any{
		"client_id": "synthetic-web-client", "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace", "chatgpt_user_id": "user"},
	})
	raw, err := json.Marshal(map[string]any{"accessToken": web, "user": map[string]any{"id": "user", "email": email}, "account": map[string]any{"id": "workspace"}})
	require.NoError(t, err)
	credentials := map[string]any{"access_token": web, "refresh_token": "synthetic-refresh", "id_token": "synthetic-id", "client_id": openai.ClientID, "email": email, "chatgpt_user_id": "user", "chatgpt_account_id": "workspace"}
	_, err = normalizeAuthorizedVaultSession(raw, email, credentials)
	require.Error(t, err)
	oauth := buildCodexImportTestJWT(t, time.Now().Add(time.Hour), map[string]any{
		"client_id": openai.ClientID, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace", "chatgpt_user_id": "user"},
	})
	credentials["access_token"] = oauth
	converted, err := normalizeAuthorizedVaultSession(raw, email, credentials)
	require.NoError(t, err)
	var document DataPayload
	require.NoError(t, json.Unmarshal(converted, &document))
	require.Equal(t, oauth, document.Accounts[0].Credentials["access_token"])
	require.NotContains(t, string(converted), web)
	credentials["chatgpt_account_id"] = "different-workspace"
	_, err = normalizeAuthorizedVaultSession(raw, email, credentials)
	require.Error(t, err)
	credentials["chatgpt_account_id"] = "workspace"
	delete(credentials, "refresh_token")
	_, err = normalizeAuthorizedVaultSession(raw, email, credentials)
	require.Error(t, err)
}

func TestVaultOAuthAuthorizationNeedsNoWebSessionAndKeepsTokenExpirySeparate(t *testing.T) {
	email := "test@example.test"
	expires := time.Now().Add(10 * 24 * time.Hour).Truncate(time.Second)
	token := buildCodexImportTestJWT(t, expires, map[string]any{
		"client_id": openai.ClientID, "https://api.openai.com/profile": map[string]any{"email": email},
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace", "chatgpt_user_id": "user"},
	})
	credentials := map[string]any{"access_token": token, "refresh_token": "synthetic-refresh", "id_token": "synthetic-id", "client_id": openai.ClientID, "email": email, "chatgpt_user_id": "user", "chatgpt_account_id": "workspace", "expires_at": expires.Format(time.RFC3339)}
	raw, err := normalizeVaultOAuthAuthorization(email, credentials)
	require.NoError(t, err)
	var document DataPayload
	require.NoError(t, json.Unmarshal(raw, &document))
	require.Len(t, document.Accounts, 1)
	require.Nil(t, document.Accounts[0].ExpiresAt)
	require.Equal(t, expires.Format(time.RFC3339), document.Accounts[0].Credentials["expires_at"])
	require.NotContains(t, string(raw), "sessionToken")
	_, err = normalizeVaultOAuthAuthorization("other@example.test", credentials)
	require.Error(t, err)
	delete(credentials, "refresh_token")
	_, err = normalizeVaultOAuthAuthorization(email, credentials)
	require.Error(t, err)
}
