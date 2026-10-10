package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func normalizeVaultSession(raw json.RawMessage, email string) (json.RawMessage, error) {
	if !service.ValidateVaultSessionIdentity(raw, email) {
		return nil, service.ErrVaultRotationInvalid
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return nil, service.ErrVaultRotationInvalid
	}
	var identity struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if json.Unmarshal(raw, &identity) != nil || identity.Account.ID == "" {
		return nil, service.ErrVaultRotationInvalid
	}
	item, err := normalizeCodexImportEntry(codexImportEntry{Index: 1, Value: value})
	if err != nil || !strings.EqualFold(item.Email, email) || item.UserID != identity.User.ID || item.AccountID != identity.Account.ID || item.TokenExpiresAt == nil || !item.TokenExpiresAt.After(time.Now()) {
		return nil, service.ErrVaultRotationInvalid
	}
	claims, err := decodeCodexJWTClaims(item.AccessToken)
	if err != nil {
		return nil, service.ErrVaultRotationInvalid
	}
	if claims.OpenAIAuth != nil {
		if claims.OpenAIAuth.ChatGPTUserID != "" && claims.OpenAIAuth.ChatGPTUserID != item.UserID {
			return nil, service.ErrVaultRotationInvalid
		}
		if claims.OpenAIAuth.ChatGPTAccountID != "" && claims.OpenAIAuth.ChatGPTAccountID != item.AccountID {
			return nil, service.ErrVaultRotationInvalid
		}
	}
	payload, err := decodeCodexJWTSegment(strings.Split(item.AccessToken, ".")[1])
	if err != nil {
		return nil, service.ErrVaultRotationInvalid
	}
	defer clear(payload)
	var tokenValue map[string]any
	if json.Unmarshal(payload, &tokenValue) != nil {
		return nil, service.ErrVaultRotationInvalid
	}
	if tokenEmail := firstCodexString(tokenValue, []string{"https://api.openai.com/profile", "email"}, []string{"email"}); tokenEmail != "" && !strings.EqualFold(tokenEmail, email) {
		return nil, service.ErrVaultRotationInvalid
	}
	item.Credentials["account_id"] = item.AccountID
	item.Credentials["workspace_id"] = item.AccountID
	expires := item.TokenExpiresAt.Unix()
	autoPause := true
	return json.Marshal(DataPayload{ExportedAt: time.Now().UTC().Format(time.RFC3339), Proxies: []DataProxy{}, Accounts: []DataAccount{{Name: email, Platform: "openai", Type: "oauth", Credentials: item.Credentials, Extra: item.Extra, Concurrency: 3, Priority: 50, ExpiresAt: &expires, AutoPauseOnExpired: &autoPause}}})
}
func (h *AccountVaultRotationHandler) importVaultSession(ctx context.Context, raw json.RawMessage, email string) (int64, json.RawMessage, error) {
	if h.accounts == nil {
		return 0, nil, service.ErrVaultRotationInvalid
	}
	var document DataPayload
	if json.Unmarshal(raw, &document) != nil || len(document.Accounts) != 1 {
		return 0, nil, service.ErrVaultRotationInvalid
	}
	value := document.Accounts[0].Credentials
	if document.Accounts[0].Name != email || validateVaultOAuthCredentials(value, email, "", "") != nil {
		return 0, nil, service.ErrVaultRotationInvalid
	}
	// Reuse the existing identity matching, credential merge, expiry validation,
	// default group binding and token cache invalidation rules for OAuth imports.
	result, err := h.accounts.importCodexSessions(ctx, CodexSessionImportRequest{Name: email}, []codexImportEntry{{Index: 1, Value: value}})
	if err != nil || result.Failed != 0 || len(result.Items) != 1 || result.Items[0].AccountID <= 0 {
		return 0, nil, service.ErrVaultRotationInvalid
	}
	id := result.Items[0].AccountID
	account, err := h.accounts.adminService.GetAccount(ctx, id)
	if err != nil || account == nil {
		return 0, nil, service.ErrVaultRotationInvalid
	}
	// Match the system's reauthorization recovery: clear a previous credential
	// error after storing fresh OAuth tokens, without enabling disabled accounts.
	if result.Items[0].Action == "updated" && account.Status == service.StatusError {
		account, err = h.accounts.adminService.ClearAccountError(ctx, id)
		if err != nil || account == nil {
			return 0, nil, service.ErrVaultRotationInvalid
		}
	}
	var expires *int64
	if account.ExpiresAt != nil {
		v := account.ExpiresAt.Unix()
		expires = &v
	}
	exported, err := json.Marshal(DataPayload{ExportedAt: time.Now().UTC().Format(time.RFC3339), Proxies: []DataProxy{}, Accounts: []DataAccount{{Name: account.Name, Notes: account.Notes, Platform: account.Platform, Type: account.Type, Credentials: account.Credentials, Extra: account.Extra, Concurrency: account.Concurrency, Priority: account.Priority, RateMultiplier: account.RateMultiplier, ExpiresAt: expires, AutoPauseOnExpired: &account.AutoPauseOnExpired}}})
	return id, exported, err
}

// Web Session tokens and Codex OAuth tokens are different credentials. Only a
// server-side PKCE exchange may produce the credentials imported by this flow.
func validateVaultOAuthCredentials(value map[string]any, email, userID, accountID string) error {
	item, err := normalizeCodexImportEntry(codexImportEntry{Index: 1, Value: value})
	if err != nil || !strings.EqualFold(item.Email, email) || item.UserID == "" || item.AccountID == "" ||
		item.RefreshToken == "" || item.IDToken == "" || item.TokenExpiresAt == nil || !item.TokenExpiresAt.After(time.Now()) ||
		(userID != "" && item.UserID != userID) || (accountID != "" && item.AccountID != accountID) {
		return service.ErrVaultRotationInvalid
	}
	claims, err := decodeCodexJWTClaims(item.AccessToken)
	if err != nil || claims.OpenAIAuth == nil || claims.OpenAIAuth.ChatGPTUserID != item.UserID || claims.OpenAIAuth.ChatGPTAccountID != item.AccountID {
		return service.ErrVaultRotationInvalid
	}
	payload, err := decodeCodexJWTSegment(strings.Split(item.AccessToken, ".")[1])
	if err != nil {
		return service.ErrVaultRotationInvalid
	}
	defer clear(payload)
	var tokenValue map[string]any
	if json.Unmarshal(payload, &tokenValue) != nil || tokenValue["client_id"] != openai.ClientID || value["client_id"] != openai.ClientID {
		return service.ErrVaultRotationInvalid
	}
	if tokenEmail := firstCodexString(tokenValue, []string{"https://api.openai.com/profile", "email"}, []string{"email"}); tokenEmail != "" && !strings.EqualFold(tokenEmail, email) {
		return service.ErrVaultRotationInvalid
	}
	return nil
}

func normalizeAuthorizedVaultSession(raw json.RawMessage, email string, credentials map[string]any) (json.RawMessage, error) {
	validated, err := normalizeVaultSession(raw, email)
	if err != nil {
		return nil, err
	}
	defer clear(validated)
	var document DataPayload
	if json.Unmarshal(validated, &document) != nil || len(document.Accounts) != 1 {
		return nil, service.ErrVaultRotationInvalid
	}
	old := document.Accounts[0].Credentials
	if validateVaultOAuthCredentials(credentials, email, codexCredentialString(old, "chatgpt_user_id"), codexCredentialString(old, "chatgpt_account_id")) != nil {
		return nil, service.ErrVaultRotationInvalid
	}
	credentials["account_id"] = credentials["chatgpt_account_id"]
	credentials["workspace_id"] = credentials["chatgpt_account_id"]
	document.Accounts[0].Credentials = credentials
	claims, _ := decodeCodexJWTClaims(codexCredentialString(credentials, "access_token"))
	document.Accounts[0].ExpiresAt = &claims.Exp
	return json.Marshal(document)
}

func normalizeVaultOAuthAuthorization(email string, credentials map[string]any) (json.RawMessage, error) {
	if validateVaultOAuthCredentials(credentials, email, "", "") != nil {
		return nil, service.ErrVaultRotationInvalid
	}
	credentials["account_id"] = credentials["chatgpt_account_id"]
	credentials["workspace_id"] = credentials["chatgpt_account_id"]
	// Token expiry is in credentials.expires_at. Account expiry is an optional
	// administrator limit and must not pause a refreshable account after 10 days.
	return json.Marshal(DataPayload{ExportedAt: time.Now().UTC().Format(time.RFC3339), Proxies: []DataProxy{}, Accounts: []DataAccount{{Name: email, Platform: "openai", Type: "oauth", Credentials: credentials, Concurrency: 3, Priority: 50}}})
}

func (h *AccountVaultRotationHandler) WorkerAuthorizeSession(c *gin.Context) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
		Revision   int64  `json:"revision"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	if h.accounts == nil || h.accounts.openaiOAuthService == nil {
		response.ErrorFrom(c, service.ErrAccountVaultUnavailable)
		return
	}
	job, authURL, err := h.rotation.BeginSessionAuthorization(c.Request.Context(), grant, c.Param("job"), req.LeaseToken, req.Revision, func() (string, string, error) {
		result, err := h.accounts.openaiOAuthService.GenerateAuthURL(c.Request.Context(), nil, "", "openai")
		if err != nil {
			return "", "", err
		}
		return result.SessionID, result.AuthURL, nil
	})
	if !response.ErrorFrom(c, err) {
		response.Success(c, gin.H{"job": job, "auth_url": authURL})
	}
}
func (h *AccountVaultRotationHandler) QueueSessions(c *gin.Context) {
	var req struct {
		IDs         []int64 `json:"ids"`
		Concurrency int     `json:"concurrency"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.QueueSessions(c.Request.Context(), actor, req.IDs, req.Concurrency)
	if !response.ErrorFrom(c, err) {
		response.Success(c, result)
	}
}
func (h *AccountVaultRotationHandler) QuerySessions(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.QuerySessions(c.Request.Context(), actor, req.IDs)
	if err == nil && h.accounts != nil {
		for i := range result {
			if result[i].GatewayAccountID <= 0 {
				continue
			}
			account, getErr := h.accounts.adminService.GetAccount(c.Request.Context(), result[i].GatewayAccountID)
			if getErr == nil && account != nil {
				result[i].CredentialExpiresAt = codexCredentialString(account.Credentials, "expires_at")
			}
		}
	}
	if !response.ErrorFrom(c, err) {
		response.Success(c, gin.H{"jobs": result})
	}
}
func (h *AccountVaultRotationHandler) ExportSessions(c *gin.Context) {
	var req struct {
		IDs    []int64 `json:"ids"`
		Format string  `json:"format"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.ExportSessions(c.Request.Context(), actor, req.IDs, req.Format)
	if !response.ErrorFrom(c, err) {
		response.Success(c, result)
	}
}
func (h *AccountVaultRotationHandler) WorkerSaveSession(c *gin.Context) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
		Revision   int64  `json:"revision"`
		OAuth      struct {
			Code  string `json:"code"`
			State string `json:"state"`
		} `json:"oauth"`
	}
	if !bindVaultJSON(c, &req, 16384, "lease_token", "revision", "oauth") {
		return
	}
	if h.accounts == nil || h.accounts.openaiOAuthService == nil || req.OAuth.Code == "" || len(req.OAuth.Code) > 8192 || req.OAuth.State == "" || len(req.OAuth.State) > 256 {
		response.ErrorFrom(c, service.ErrVaultRotationInvalid)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	result, err := h.rotation.SaveOAuthAuthorization(ctx, grant, c.Param("job"), req.LeaseToken, req.Revision, func(email, sessionID string) (json.RawMessage, error) {
		info, err := h.accounts.openaiOAuthService.ExchangeCode(ctx, &service.OpenAIExchangeCodeInput{SessionID: sessionID, Code: req.OAuth.Code, State: req.OAuth.State})
		if err != nil {
			slog.Warn("vault_oauth_exchange_failed", "job_id", c.Param("job"), "reason", vaultOAuthExchangeFailureCode(err), "status_code", infraerrors.Code(err))
			return nil, service.ErrVaultRotationInvalid
		}
		defer func() { info.AccessToken = ""; info.RefreshToken = ""; info.IDToken = "" }()
		payload, err := normalizeVaultOAuthAuthorization(email, h.accounts.openaiOAuthService.BuildAccountCredentials(info))
		if err != nil {
			slog.Warn("vault_oauth_validation_failed", "job_id", c.Param("job"), "email_matches", strings.EqualFold(info.Email, email), "has_refresh_token", info.RefreshToken != "", "has_id_token", info.IDToken != "", "has_user_id", info.ChatGPTUserID != "", "has_account_id", info.ChatGPTAccountID != "", "client_matches", info.ClientID == openai.ClientID)
		}
		return payload, err
	})
	if !response.ErrorFrom(c, err) {
		response.Success(c, gin.H{"job": result})
	}
}

// Return only fixed codes: upstream error bodies can contain credentials or
// callbacks and must never be written verbatim to browser-helper diagnostics.
func vaultOAuthExchangeFailureCode(err error) string {
	if err == nil {
		return "none"
	}
	message := strings.ToLower(err.Error())
	for _, code := range []string{"unsupported_country_region_territory", "invalid_grant", "invalid_client", "access_denied", "token_revoked", "refresh_token_invalidated"} {
		if strings.Contains(message, code) {
			return code
		}
	}
	switch infraerrors.Reason(err) {
	case "OPENAI_OAUTH_SESSION_NOT_FOUND":
		return "session_expired"
	case "OPENAI_OAUTH_INVALID_STATE", "OPENAI_OAUTH_STATE_REQUIRED":
		return "state_invalid"
	case "OPENAI_OAUTH_PROXY_NOT_FOUND", "OPENAI_DEFAULT_PROXY_INVALID":
		return "proxy_configuration_invalid"
	}
	return "exchange_failed"
}
func (h *AccountVaultRotationHandler) WorkerCompleteSession(c *gin.Context) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
		Revision   int64  `json:"revision"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	result, err := h.rotation.CompleteSession(c.Request.Context(), grant, c.Param("job"), req.LeaseToken, req.Revision, h.importVaultSession)
	if !response.ErrorFrom(c, err) {
		response.Success(c, gin.H{"job": result})
	}
}
