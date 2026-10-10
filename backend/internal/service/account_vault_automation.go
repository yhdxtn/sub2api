package service

import (
	"context"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/google/uuid"
	"strings"
	"sync"
	"time"
)

type VaultAutomationSettings struct {
	Enabled              bool  `json:"enabled"`
	ActorID              int64 `json:"-"`
	TokenVersion         int64 `json:"-"`
	QueryIntervalSeconds int   `json:"query_interval_seconds"`
}
type VaultAccountHealth struct {
	AccountID        int64               `json:"account_id"`
	GatewayAccountID int64               `json:"gateway_account_id"`
	Status           string              `json:"status"`
	ErrorCode        string              `json:"error_code,omitempty"`
	CheckedAt        time.Time           `json:"checked_at"`
	Quota            *VaultQuotaSnapshot `json:"quota,omitempty"`
}
type VaultAutomationAccount struct {
	AccountID, GatewayAccountID int64
	ActiveJob, PausedJob        bool
}
type AccountVaultAutomationRepository interface {
	AutomationSettings(context.Context) (*VaultAutomationSettings, error)
	SaveAutomationSettings(context.Context, VaultAutomationSettings) error
	LinkedAutomationAccounts(context.Context) ([]VaultAutomationAccount, error)
	AutomationHealth(context.Context, []int64) ([]VaultAccountHealth, error)
	SaveAutomationHealth(context.Context, VaultAccountHealth) error
	ClaimReauthorization(context.Context, int64, string, time.Time) (bool, error)
}
type vaultAutomation struct {
	rotation *AccountVaultRotationService
	repo     AccountVaultAutomationRepository
	usage    *AccountUsageService
	mu       sync.Mutex
}

func (s *AccountVaultRotationService) ConfigureAutomation(usage *AccountUsageService) {
	repo, ok := s.repo.(AccountVaultAutomationRepository)
	if !ok || usage == nil || usage.openAIQuotaService == nil || s.automation != nil {
		return
	}
	s.automation = &vaultAutomation{rotation: s, repo: repo, usage: usage}
	// This worker lives for the server process. Durable settings and claims make
	// restarts safe; disabling the setting stops new checks/reauthorizations.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
			s.automation.scan(ctx, nil, false)
			cancel()
		}
	}()
}
func (s *AccountVaultRotationService) AutomationSettings(ctx context.Context, actorID int64) (*VaultAutomationSettings, error) {
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if s.automation == nil {
		return nil, ErrAccountVaultUnavailable
	}
	return s.automation.repo.AutomationSettings(ctx)
}
func (s *AccountVaultRotationService) SetAutomation(ctx context.Context, actorID int64, enabled bool) (*VaultAutomationSettings, error) {
	user, err := s.actor(ctx, actorID)
	if err != nil {
		return nil, err
	}
	if s.automation == nil || (enabled && !s.autoWorker.configured()) {
		return nil, ErrAccountVaultUnavailable
	}
	settings := VaultAutomationSettings{Enabled: enabled, ActorID: actorID, TokenVersion: user.TokenVersion, QueryIntervalSeconds: 60}
	if err = s.automation.repo.SaveAutomationSettings(ctx, settings); err != nil {
		return nil, rotationStorageError()
	}
	return &settings, nil
}
func (s *AccountVaultRotationService) AutomationHealth(ctx context.Context, actorID int64, ids []int64, force bool) ([]VaultAccountHealth, error) {
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if s.automation == nil || len(ids) == 0 || !validRotationIDs(ids, 200) {
		return nil, ErrVaultRotationInvalid
	}
	if force {
		if err := s.automation.scan(ctx, ids, true); err != nil {
			return nil, err
		}
	}
	rows, err := s.automation.repo.AutomationHealth(ctx, ids)
	if err != nil {
		return nil, rotationStorageError()
	}
	return rows, nil
}
func revokedCredentialError(err error) string {
	if err == nil {
		return ""
	}
	reason := infraerrors.Reason(err)
	e := infraerrors.FromError(err)
	code := e.Metadata["upstream_code"]
	if reason == "OPENAI_QUOTA_UPSTREAM_ERROR" && infraerrors.Code(err) == 401 {
		switch code {
		case "token_revoked", "token_invalidated", "refresh_token_invalidated", "refresh_token_reused", "invalid_grant":
			return code
		}
	}
	// A failed normal refresh can prevent the live quota request from starting.
	if reason == "OPENAI_QUOTA_TOKEN_UNAVAILABLE" {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "invalid_client") || strings.Contains(message, "unsupported_country_region_territory") || strings.Contains(message, "access_denied") {
			return ""
		}
		if strings.Contains(message, "access_token expired and refresh_token is missing") {
			return "expired_without_refresh_token"
		}
		for _, known := range []string{"refresh_token_invalidated", "refresh_token_reused", "invalid_refresh_token", "invalid_grant"} {
			if strings.Contains(message, known) {
				return known
			}
		}
	}
	return ""
}

// ReauthorizeInvalid checks linked accounts across all pages. Ordinary access
// token expiry is first handled by the token provider; only an explicit terminal
// credential rejection queues a new OAuth login. Network/policy failures do not.
func (s *AccountVaultRotationService) ReauthorizeInvalid(ctx context.Context, actorID int64) (*VaultReauthorizationResult, error) {
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if s.automation == nil {
		return nil, ErrAccountVaultUnavailable
	}
	a := s.automation
	if !a.mu.TryLock() {
		return nil, infraerrors.ServiceUnavailable("VAULT_QUOTA_CHECK_BUSY", "额度正在查询，请稍后重试")
	}
	defer a.mu.Unlock()
	linked, err := a.repo.LinkedAutomationAccounts(ctx)
	if err != nil {
		return nil, rotationStorageError()
	}
	ids := make([]int64, 0, len(linked))
	for _, v := range linked {
		ids = append(ids, v.AccountID)
	}
	old, err := a.repo.AutomationHealth(ctx, ids)
	if err != nil {
		return nil, rotationStorageError()
	}
	previous := map[int64]VaultAccountHealth{}
	for _, h := range old {
		previous[h.AccountID] = h
	}
	result := &VaultReauthorizationResult{Rows: []AccountVaultRotationQueueRow{}}
	for _, v := range linked {
		account, err := a.usage.accountRepo.GetByID(ctx, v.GatewayAccountID)
		if err != nil || account == nil || !account.IsOpenAIOAuth() || account.IsShadow() {
			result.Skipped++
			continue
		}
		expires := account.GetCredentialAsTime("expires_at")
		priorCode := previous[v.AccountID].ErrorCode
		if !terminalVaultCredentialCode(priorCode) && priorCode != "automatic_attempt_limited" && priorCode != "reauthorization_queue_failed" && account.Status != StatusError && (expires == nil || expires.After(time.Now())) {
			continue
		}
		if v.ActiveJob || v.PausedJob {
			result.Skipped++
			continue
		}
		if ctx.Err() != nil {
			result.Skipped++
			continue
		}
		result.Checked++
		fingerprint := rotationHash(account.GetCredential("access_token") + "\x00" + account.GetCredential("refresh_token"))
		quota, queryErr := a.usage.queryLiveQuota(ctx, account.ID)
		needsLogin := false
		health := VaultAccountHealth{AccountID: v.AccountID, GatewayAccountID: account.ID, CheckedAt: time.Now(), Status: "live", Quota: quota}
		if queryErr == nil {
			result.Refreshed++
		} else {
			health.Status = "error"
			health.ErrorCode = vaultQuotaFailureCode(queryErr)
			if revokedCredentialError(queryErr) != "" {
				current, getErr := a.usage.accountRepo.GetByID(ctx, account.ID)
				if getErr == nil && current != nil && fingerprint == rotationHash(current.GetCredential("access_token")+"\x00"+current.GetCredential("refresh_token")) {
					needsLogin = true
				} else {
					result.Skipped++
				}
			} else {
				result.Failed++
			}
		}
		if a.repo.SaveAutomationHealth(ctx, health) != nil {
			return nil, rotationStorageError()
		}
		if needsLogin {
			queued, err := s.QueueSessions(ctx, actorID, []int64{v.AccountID}, 2)
			if err != nil {
				result.Failed++
				continue
			}
			result.Rows = append(result.Rows, queued.Rows...)
		}
	}
	return result, nil
}

type VaultReauthorizationResult struct {
	Rows      []AccountVaultRotationQueueRow `json:"rows"`
	Checked   int                            `json:"checked"`
	Refreshed int                            `json:"refreshed"`
	Failed    int                            `json:"failed"`
	Skipped   int                            `json:"skipped"`
}

func terminalVaultCredentialCode(code string) bool {
	switch code {
	case "token_revoked", "token_invalidated", "refresh_token_invalidated", "refresh_token_reused", "invalid_refresh_token", "invalid_grant", "expired_without_refresh_token":
		return true
	}
	return false
}
func vaultQuotaFailureCode(err error) string {
	if code := revokedCredentialError(err); code != "" {
		return code
	}
	switch infraerrors.Reason(err) {
	case "OPENAI_QUOTA_REQUEST_FAILED":
		return "quota_network_error"
	case "OPENAI_QUOTA_TOKEN_UNAVAILABLE":
		return "quota_token_unavailable"
	case "OPENAI_QUOTA_INVALID_RESPONSE":
		return "quota_invalid_response"
	case "OPENAI_QUOTA_STORAGE_FAILED":
		return "quota_storage_failed"
	case "OPENAI_QUOTA_UPSTREAM_ERROR":
		switch infraerrors.Code(err) {
		case 401:
			return "quota_unauthorized"
		case 403:
			return "quota_access_denied"
		case 429:
			return "quota_rate_limited"
		}
	}
	return "quota_query_failed"
}
func (a *vaultAutomation) scan(ctx context.Context, ids []int64, force bool) error {
	if !a.mu.TryLock() {
		return infraerrors.ServiceUnavailable("VAULT_QUOTA_CHECK_BUSY", "额度正在查询，请稍后重试")
	}
	defer a.mu.Unlock()
	settings, err := a.repo.AutomationSettings(ctx)
	if err != nil {
		return rotationStorageError()
	}
	if !settings.Enabled && !force {
		return nil
	}
	owner, ownerErr := a.rotation.actor(ctx, settings.ActorID)
	authorized := settings.Enabled && ownerErr == nil && owner.TokenVersion == settings.TokenVersion
	if settings.Enabled && !authorized {
		settings.Enabled = false
		_ = a.repo.SaveAutomationSettings(ctx, *settings)
		if !force {
			return nil
		}
	}
	linked, err := a.repo.LinkedAutomationAccounts(ctx)
	if err != nil {
		return rotationStorageError()
	}
	requested := map[int64]bool{}
	for _, id := range ids {
		requested[id] = true
	}
	allIDs := make([]int64, 0, len(linked))
	for _, v := range linked {
		allIDs = append(allIDs, v.AccountID)
	}
	old, _ := a.repo.AutomationHealth(ctx, allIDs)
	previous := map[int64]VaultAccountHealth{}
	for _, h := range old {
		previous[h.AccountID] = h
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 2)
	failures := make(chan error, len(linked))
	for _, v := range linked {
		if ctx.Err() != nil {
			break
		}
		if len(ids) > 0 && !requested[v.AccountID] {
			continue
		}
		if !force && previous[v.AccountID].Status != "reauthorizing" && time.Since(previous[v.AccountID].CheckedAt) < time.Minute {
			continue
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Add(1)
		go func(v VaultAutomationAccount) {
			defer wg.Done()
			defer func() { <-slots }()
			if err := a.check(ctx, v, previous[v.AccountID], settings.ActorID, authorized); err != nil {
				failures <- err
			}
		}(v)
	}
	wg.Wait()
	select {
	case err := <-failures:
		return err
	default:
	}
	return ctx.Err()
}
func (a *vaultAutomation) check(ctx context.Context, v VaultAutomationAccount, _ VaultAccountHealth, actorID int64, authorized bool) (checkErr error) {
	health := VaultAccountHealth{AccountID: v.AccountID, GatewayAccountID: v.GatewayAccountID, Status: "error", CheckedAt: time.Now()}
	defer func() {
		if a.repo.SaveAutomationHealth(ctx, health) != nil {
			checkErr = rotationStorageError()
		}
	}()
	account, err := a.usage.accountRepo.GetByID(ctx, v.GatewayAccountID)
	if err != nil || account == nil || !account.IsOpenAIOAuth() || account.IsShadow() || account.Status == StatusDisabled {
		health.ErrorCode = "account_unavailable"
		return nil
	}
	if v.ActiveJob {
		health.Status = "reauthorizing"
		health.ErrorCode = "active_job"
		if authorized {
			a.rotation.ensureWorker(ctx, actorID)
		}
		return nil
	}
	if v.PausedJob {
		health.Status = "manual_required"
		health.ErrorCode = "paused_job"
		return nil
	}
	// Read live quota without inference. Failed reads never expose an old snapshot
	// as current quota, and 403/429/network failures do not start browser login.
	quota, queryErr := a.usage.queryLiveQuota(ctx, account.ID)
	if queryErr == nil {
		health.Status = "live"
		health.Quota = quota
		return nil
	}
	code := revokedCredentialError(queryErr)
	health.ErrorCode = vaultQuotaFailureCode(queryErr)
	if code == "" || !authorized {
		return nil
	}
	// Insert the observation before the durable claim, and fail closed if storage is unavailable.
	if a.repo.SaveAutomationHealth(ctx, health) != nil {
		return rotationStorageError()
	}
	// Claim the exact failed token set durably. A concurrent new import must not
	// be replaced by a recovery queued for stale credentials.
	current, err := a.usage.accountRepo.GetByID(ctx, account.ID)
	fingerprint := rotationHash(account.GetCredential("access_token") + "\x00" + account.GetCredential("refresh_token"))
	if err != nil || current == nil || fingerprint != rotationHash(current.GetCredential("access_token")+"\x00"+current.GetCredential("refresh_token")) {
		return nil
	}
	settings, settingsErr := a.repo.AutomationSettings(ctx)
	owner, ownerErr := a.rotation.actor(ctx, actorID)
	if settingsErr != nil || settings == nil || !settings.Enabled || settings.ActorID != actorID || ownerErr != nil || owner.TokenVersion != settings.TokenVersion {
		return nil
	}
	claimed, err := a.repo.ClaimReauthorization(ctx, v.AccountID, fingerprint, time.Now())
	if err != nil || !claimed {
		health.Status = "manual_required"
		health.ErrorCode = "automatic_attempt_limited"
		return nil
	}
	job, _, err := a.rotation.repo.QueueSession(ctx, actorID, v.AccountID, uuid.NewString(), time.Now())
	if err != nil || job == nil {
		health.Status = "manual_required"
		health.ErrorCode = "reauthorization_queue_failed"
		return nil
	}
	health.Status = "reauthorizing"
	health.ErrorCode = ""
	a.rotation.ensureWorker(ctx, actorID)
	return nil
}
