package service

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

type VaultSessionSnapshot struct {
	Session json.RawMessage `json:"session"`
	Import  json.RawMessage `json:"import"`
}
type VaultSessionNormalizer func(json.RawMessage, string) (json.RawMessage, error)
type VaultSessionImporter func(context.Context, json.RawMessage, string) (int64, json.RawMessage, error)

// OAuth authorization does not require or retain a web Session or its cookies.
// Reuse the fenced PKCE intent and encrypted credential snapshot for legacy jobs.
func (s *AccountVaultRotationService) SaveOAuthAuthorization(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, exchange func(string, string) (json.RawMessage, error)) (*AccountVaultRotationDTO, error) {
	if exchange == nil {
		return nil, ErrVaultRotationInvalid
	}
	return s.SaveAuthorizedSession(ctx, grant, id, token, revision, json.RawMessage(`null`), func(_ json.RawMessage, email, sessionID string) (json.RawMessage, error) {
		return exchange(email, sessionID)
	})
}

// The PKCE session identifier stays encrypted on the server and is bound to
// the actor, vault row, job and lease. Workers receive only the authorize URL.
type vaultSessionAuthorization struct {
	OAuthSessionID string `json:"oauth_session_id"`
}

func (s *AccountVaultRotationService) BeginSessionAuthorization(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, generate func() (string, string, error)) (*AccountVaultRotationDTO, string, error) {
	if generate == nil {
		return nil, "", ErrVaultRotationInvalid
	}
	var authURL string
	job, err := s.workerUpdate(ctx, grant, id, token, revision, func(j AccountVaultRotationJob, r AccountVaultRecord) (AccountVaultRotationMutation, error) {
		if j.Kind != "session" || j.Phase != "login" || j.BaseCipherHash != rotationHash(r.EncryptedData) {
			return AccountVaultRotationMutation{}, ErrVaultRotationConflict
		}
		sessionID, url, err := generate()
		if err != nil || sessionID == "" || url == "" {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		raw, err := json.Marshal(vaultSessionAuthorization{OAuthSessionID: sessionID})
		if err != nil {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		defer clear(raw)
		j.PendingEncrypted, err = s.vault.cipher.EncryptSession(j.ID, r.VaultID, r.Email, raw)
		if err != nil {
			return AccountVaultRotationMutation{}, ErrAccountVaultUnavailable
		}
		authURL = url
		j.Revision++
		j.Progress = "awaiting_provider"
		j.UpdatedAt = s.now()
		return AccountVaultRotationMutation{Job: j, Event: "session_authorization_started"}, nil
	})
	if err != nil {
		return nil, "", err
	}
	dto := job.Public()
	return &dto, authURL, nil
}

func (s *AccountVaultRotationService) SaveAuthorizedSession(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, raw json.RawMessage, exchange func(json.RawMessage, string, string) (json.RawMessage, error)) (*AccountVaultRotationDTO, error) {
	if exchange == nil {
		return nil, ErrVaultRotationInvalid
	}
	return s.saveSession(ctx, grant, id, token, revision, raw, func(j AccountVaultRotationJob, r AccountVaultRecord) (json.RawMessage, error) {
		intent, err := s.vault.cipher.DecryptSession(j.ID, r.VaultID, r.Email, j.PendingEncrypted)
		if err != nil {
			return nil, ErrVaultRotationInvalid
		}
		defer clear(intent)
		var authorization vaultSessionAuthorization
		if json.Unmarshal(intent, &authorization) != nil || authorization.OAuthSessionID == "" {
			return nil, ErrVaultRotationInvalid
		}
		return exchange(raw, r.Email, authorization.OAuthSessionID)
	})
}

func (s *AccountVaultRotationService) QueueSessions(ctx context.Context, actorID int64, ids []int64, concurrency int) (*AccountVaultRotationQueueResult, error) {
	if concurrency < 1 || concurrency > VaultRotationMaxConcurrency || len(ids) == 0 || !validRotationIDs(ids, 200) {
		return nil, ErrVaultRotationInvalid
	}
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if err := s.repo.SetConcurrency(ctx, actorID, concurrency); err != nil {
		return nil, rotationError(err)
	}
	result := &AccountVaultRotationQueueResult{Rows: make([]AccountVaultRotationQueueRow, 0, len(ids))}
	for _, id := range ids {
		job, status, err := s.repo.QueueSession(ctx, actorID, id, uuid.NewString(), s.now())
		row := AccountVaultRotationQueueRow{AccountID: id, Status: status}
		if err != nil {
			row.Status = "error"
			row.ErrorCode = "queue_failed"
			if err == ErrVaultRotationActive {
				row.Status = "blocked"
				row.ErrorCode = "active_job"
			}
		}
		if job != nil {
			dto := job.Public()
			row.Job = &dto
		}
		result.Rows = append(result.Rows, row)
	}
	for _, row := range result.Rows {
		if row.Job != nil && row.Job.Status == "queued" {
			s.ensureWorker(ctx, actorID)
			break
		}
	}
	for i := range result.Rows {
		s.decorateWorker(actorID, result.Rows[i].Job)
	}
	return result, nil
}
func (s *AccountVaultRotationService) QuerySessions(ctx context.Context, actorID int64, ids []int64) ([]AccountVaultRotationDTO, error) {
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if !validRotationIDs(ids, 200) {
		return nil, ErrVaultRotationInvalid
	}
	jobs, err := s.repo.QuerySessions(ctx, actorID, ids)
	if err != nil {
		return nil, rotationError(err)
	}
	result := make([]AccountVaultRotationDTO, 0, len(jobs))
	for _, j := range jobs {
		if j.Status == "queued" {
			s.ensureWorker(ctx, actorID)
		}
		dto := j.Public()
		s.decorateWorker(actorID, &dto)
		result = append(result, dto)
	}
	return result, nil
}
func (s *AccountVaultRotationService) SaveSession(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, raw json.RawMessage, normalize VaultSessionNormalizer) (*AccountVaultRotationDTO, error) {
	if normalize == nil {
		return nil, ErrVaultRotationInvalid
	}
	return s.saveSession(ctx, grant, id, token, revision, raw, func(_ AccountVaultRotationJob, r AccountVaultRecord) (json.RawMessage, error) {
		return normalize(raw, r.Email)
	})
}

func (s *AccountVaultRotationService) saveSession(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, raw json.RawMessage, normalize func(AccountVaultRotationJob, AccountVaultRecord) (json.RawMessage, error)) (*AccountVaultRotationDTO, error) {
	if len(raw) == 0 || len(raw) > 131072 || normalize == nil {
		return nil, ErrVaultRotationInvalid
	}
	job, err := s.workerUpdate(ctx, grant, id, token, revision, func(j AccountVaultRotationJob, r AccountVaultRecord) (AccountVaultRotationMutation, error) {
		if j.Kind != "session" || j.Phase != "login" || j.BaseCipherHash != rotationHash(r.EncryptedData) {
			return AccountVaultRotationMutation{}, ErrVaultRotationConflict
		}
		converted, err := normalize(j, r)
		if err != nil {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		defer clear(converted)
		snapshot, err := json.Marshal(VaultSessionSnapshot{Session: raw, Import: converted})
		if err != nil {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		defer clear(snapshot)
		j.PendingEncrypted, err = s.vault.cipher.EncryptSession(j.ID, r.VaultID, r.Email, snapshot)
		if err != nil {
			return AccountVaultRotationMutation{}, ErrAccountVaultUnavailable
		}
		j.Phase = "prepared"
		j.Progress = "prepared"
		j.Revision++
		j.UpdatedAt = s.now()
		return AccountVaultRotationMutation{Job: j, Event: "session_saved"}, nil
	})
	if err != nil {
		return nil, err
	}
	dto := job.Public()
	return &dto, nil
}
func (s *AccountVaultRotationService) openSession(j AccountVaultRotationJob, r AccountVaultRecord) (*VaultSessionSnapshot, error) {
	if j.Kind != "session" || j.PendingEncrypted == "" {
		return nil, ErrVaultRotationInvalid
	}
	raw, err := s.vault.cipher.DecryptSession(j.ID, r.VaultID, r.Email, j.PendingEncrypted)
	if err != nil {
		return nil, ErrAccountVaultUnavailable
	}
	defer clear(raw)
	var snapshot VaultSessionSnapshot
	if json.Unmarshal(raw, &snapshot) != nil || !json.Valid(snapshot.Session) || !json.Valid(snapshot.Import) {
		return nil, ErrVaultRotationInvalid
	}
	return &snapshot, nil
}
func (s *AccountVaultRotationService) CompleteSession(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, importer VaultSessionImporter) (*AccountVaultRotationDTO, error) {
	if importer == nil {
		return nil, ErrVaultRotationInvalid
	}
	job, err := s.workerUpdate(ctx, grant, id, token, revision, func(j AccountVaultRotationJob, r AccountVaultRecord) (AccountVaultRotationMutation, error) {
		if j.Kind != "session" || j.Phase != "prepared" || j.BaseCipherHash != rotationHash(r.EncryptedData) {
			return AccountVaultRotationMutation{}, ErrVaultRotationConflict
		}
		snapshot, err := s.openSession(j, r)
		if err != nil {
			return AccountVaultRotationMutation{}, err
		}
		defer clear(snapshot.Session)
		defer clear(snapshot.Import)
		gatewayID, exported, err := importer(ctx, snapshot.Import, r.Email)
		if err != nil || gatewayID <= 0 {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		snapshot.Import = exported
		raw, err := json.Marshal(snapshot)
		if err != nil {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		defer clear(raw)
		j.PendingEncrypted, err = s.vault.cipher.EncryptSession(j.ID, r.VaultID, r.Email, raw)
		if err != nil {
			return AccountVaultRotationMutation{}, ErrAccountVaultUnavailable
		}
		now := s.now()
		j.Status = "completed"
		j.Phase = "completed"
		j.Progress = "completed"
		j.CompletedAt = &now
		j.UpdatedAt = now
		j.GatewayAccountID = gatewayID
		j.Revision++
		j.LeaseHash = ""
		j.LeaseExpiresAt = nil
		// A session completion never sets Complete: that flag is exclusively for
		// atomic replacement of the vault seed and insertion of the MFA ledger.
		return AccountVaultRotationMutation{Job: j, Event: "session_imported"}, nil
	})
	if err != nil {
		return nil, err
	}
	dto := job.Public()
	return &dto, nil
}
func (s *AccountVaultRotationService) ExportSessions(ctx context.Context, actorID int64, ids []int64, format string) (json.RawMessage, error) {
	if len(ids) == 0 || !validRotationIDs(ids, 200) || (format != "session" && format != "import") {
		return nil, ErrVaultRotationInvalid
	}
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	jobs, err := s.repo.QuerySessions(ctx, actorID, ids)
	if err != nil {
		return nil, rotationError(err)
	}
	if len(jobs) != len(ids) {
		return nil, ErrVaultRotationNotFound
	}
	sessions := make([]json.RawMessage, 0, len(jobs))
	accounts := make([]json.RawMessage, 0, len(jobs))
	for _, j := range jobs {
		if j.Status != "completed" || j.Phase != "completed" || j.CompletedAt == nil {
			return nil, ErrVaultRotationConflict
		}
		r, err := s.vault.repo.GetByID(ctx, j.AccountID)
		if err != nil {
			return nil, rotationError(err)
		}
		snap, err := s.openSession(j, *r)
		if err != nil {
			return nil, err
		}
		if format == "session" {
			if string(snap.Session) == "null" {
				return nil, ErrVaultRotationInvalid
			}
			sessions = append(sessions, snap.Session)
		} else {
			var document struct {
				Accounts []json.RawMessage `json:"accounts"`
			}
			if json.Unmarshal(snap.Import, &document) != nil || len(document.Accounts) != 1 {
				return nil, ErrVaultRotationInvalid
			}
			accounts = append(accounts, document.Accounts...)
		}
	}
	if format == "session" {
		if len(sessions) == 1 {
			return sessions[0], nil
		}
		return json.Marshal(sessions)
	}
	return json.Marshal(struct {
		ExportedAt string            `json:"exported_at"`
		Proxies    []any             `json:"proxies"`
		Accounts   []json.RawMessage `json:"accounts"`
	}{s.now().UTC().Format("2006-01-02T15:04:05Z"), []any{}, accounts})
}

// Verify the server-side expected identity as well as the browser's check.
func ValidateVaultSessionIdentity(raw json.RawMessage, email string) bool {
	var value struct {
		AccessToken string `json:"accessToken"`
		User        struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	return json.Unmarshal(raw, &value) == nil && len(value.AccessToken) > 0 && len(value.AccessToken) <= 32768 && value.User.ID != "" && strings.EqualFold(value.User.Email, email)
}
