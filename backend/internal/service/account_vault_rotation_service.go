package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/accountvault"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/google/uuid"
)

type AccountVaultRotationService struct {
	repo       AccountVaultRotationRepository
	vault      *AccountVaultService
	users      UserRepository
	now        func() time.Time
	autoWorker *accountVaultAutoWorker
	automation *vaultAutomation
}

func NewAccountVaultRotationService(repo AccountVaultRotationRepository, vault *AccountVaultService, users UserRepository) *AccountVaultRotationService {
	return &AccountVaultRotationService{repo: repo, vault: vault, users: users, now: time.Now, autoWorker: newAccountVaultAutoWorker()}
}
func rotationStorageError() error {
	return infraerrors.ServiceUnavailable("ACCOUNT_VAULT_ROTATION_STORAGE_FAILED", "换绑状态暂时无法保存，请暂停上游操作后重试")
}
func rotationError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrVaultRotationConflict, ErrVaultRotationActive, ErrVaultRotationBlocked, ErrVaultRotationManual, ErrVaultRotationNotFound, ErrVaultWorkerUnauthorized, ErrVaultRotationInvalid, ErrAccountVaultNotFound, ErrAccountVaultKeyMismatch, ErrAccountVaultUnavailable} {
		if errors.Is(err, known) {
			return known
		}
	}
	return rotationStorageError()
}
func (s *AccountVaultRotationService) ready(ctx context.Context) error {
	if s == nil || s.vault == nil || s.repo == nil {
		return ErrAccountVaultUnavailable
	}
	return s.vault.checkKey(ctx)
}
func (s *AccountVaultRotationService) actor(ctx context.Context, id int64) (*User, error) {
	if id <= 0 || s.users == nil {
		return nil, ErrVaultWorkerUnauthorized
	}
	user, err := s.users.GetByID(ctx, id)
	if err != nil || user == nil || !user.IsActive() || !user.IsAdmin() || user.DeletedAt != nil {
		return nil, ErrVaultWorkerUnauthorized
	}
	return user, nil
}
func rotationHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func randomRotationToken() (string, error) {
	b := make([]byte, 32)
	defer clear(b)
	if _, err := rand.Read(b); err != nil {
		return "", rotationStorageError()
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func validOpaque(value string) bool {
	return len(value) > 0 && len(value) <= 512 && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0
}
func validRotationIDs(ids []int64, max int) bool {
	if len(ids) > max {
		return false
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func safeCancel(phase string) bool { return phase == "login" || phase == "prepared" }
func (j AccountVaultRotationJob) Public() AccountVaultRotationDTO {
	message := map[string]string{"queued": "等待本地浏览器助手", "login": "正在登录并确认账号", "awaiting_user": "助手会填写并点击普通登录按钮；邮件码、人机验证或 Passkey 请在浏览器中完成", "awaiting_navigation": "助手未能打开 ChatGPT；请在弹出的 Edge 无痕窗口地址栏打开 https://chatgpt.com", "awaiting_cloudflare": "等待 OpenAI 官方 Cloudflare 验证；请在浏览器中手动完成，助手会自动继续", "awaiting_provider": "官方登录跳转页正在加载，暂无需操作；助手会自动继续", "prepared": "账号与原 2FA 已核对", "disable_intent": "正在关闭原 2FA", "disabled": "原 2FA 已关闭", "enroll_intent": "正在申请新 2FA", "enrolled": "新 Secret 已加密保存", "activate_intent": "正在激活新 2FA", "verified": "已核对远端新 2FA", "completed": "远端新 2FA 已核验并保存；助手窗口会自动关闭", "paused": "换绑已暂停，请核对进度后继续", "cancelled": "任务已取消"}[j.Progress]
	if message == "" {
		message = "换绑状态已更新"
	}
	if j.ErrorCode == "enrollment_uncertain" {
		message = "申请结果不确定，需要人工核对；请勿重复关闭或申请"
	}
	if j.ErrorCode == "identity_mismatch" {
		message = "登录到的 ChatGPT 账号与账号库邮箱不一致；未修改远端 2FA，请核对账号邮箱和密码"
	}
	if strings.HasPrefix(j.ErrorCode, "identity_response_") {
		message = "ChatGPT 身份接口返回的数据格式与助手预期不符（" + j.ErrorCode + "）；未修改远端 2FA"
	}
	if j.ErrorCode == "manual_required" {
		message = "登录需要额外验证；请在本机浏览器完成验证后再恢复任务"
	}
	if j.ErrorCode == "cloudflare_challenge" {
		message = "OpenAI 登录页要求 Cloudflare 验证，等待超时后已暂停；远端 2FA 未修改"
	}
	if j.Kind == "session" {
		if j.Progress == "authorizing" {
			message = "正在选择账号并确认 OAuth 授权；普通按钮自动点击"
		}
		if j.Progress == "exchanging" {
			message = "已捕获回调 code，正在通过系统接口交换 OAuth 凭据"
		}
		if j.Progress == "awaiting_authorization" {
			message = "请在此账号的无痕窗口确认 Codex 授权；授权完成后自动核对身份并导入，2FA 不变"
		}
		if j.Phase == "login" && j.Progress == "login" && j.PendingEncrypted != "" {
			message = "正在获取并核对 OAuth 调用凭据；2FA 不变"
		}
		if j.Progress == "working" {
			message = "正在自动登录账号"
		}
		if j.Progress == "prepared" {
			message = "OAuth 凭据已加密保存，正在导入或更新系统账号"
		}
		if j.Progress == "completed" {
			message = "OAuth 授权已导入系统；助手窗口会自动关闭"
		}
		if j.Progress == "paused" {
			message = "OAuth 授权或导入已暂停，可恢复重试；2FA 未修改"
			if j.ErrorCode == "storage_failed" {
				message = "OAuth 保存或导入未确认，请恢复重试；2FA 未修改"
			}
			if j.ErrorCode == "identity_mismatch" {
				message = "授权身份与账号库不一致，未导入；请核对邮箱和密码"
			}
			if j.ErrorCode == "cloudflare_challenge" || j.ErrorCode == "manual_required" {
				message = "登录需要人工验证，等待超时后已暂停；请恢复并在弹出窗口完成验证"
			}
		}
	}
	return AccountVaultRotationDTO{Kind: j.Kind, GatewayAccountID: j.GatewayAccountID, ID: j.ID, AccountID: j.AccountID, Status: j.Status, Phase: j.Phase, Revision: j.Revision, Progress: j.Progress, Message: message, ErrorCode: j.ErrorCode, CanCancel: (j.Status == "queued" || j.Status == "paused") && safeCancel(j.Phase), CanResume: j.Status == "paused" && j.Phase != "enroll_intent", CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt, CompletedAt: j.CompletedAt}
}
func (s *AccountVaultRotationService) Queue(ctx context.Context, actorID int64, ids []int64) (*AccountVaultRotationQueueResult, error) {
	return s.queue(ctx, actorID, ids, 0)
}
func (s *AccountVaultRotationService) QueueConcurrent(ctx context.Context, actorID int64, ids []int64, concurrency int) (*AccountVaultRotationQueueResult, error) {
	if concurrency < 1 || concurrency > VaultRotationMaxConcurrency {
		return nil, ErrVaultRotationInvalid
	}
	return s.queue(ctx, actorID, ids, concurrency)
}
func (s *AccountVaultRotationService) queue(ctx context.Context, actorID int64, ids []int64, concurrency int) (*AccountVaultRotationQueueResult, error) {
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if len(ids) == 0 || !validRotationIDs(ids, 500) {
		return nil, ErrVaultRotationInvalid
	}
	if concurrency != 0 {
		if err := s.repo.SetConcurrency(ctx, actorID, concurrency); err != nil {
			return nil, rotationError(err)
		}
	}
	result := &AccountVaultRotationQueueResult{Rows: make([]AccountVaultRotationQueueRow, 0, len(ids))}
	for _, id := range ids {
		if ctx.Err() != nil {
			return nil, rotationStorageError()
		}
		row := AccountVaultRotationQueueRow{AccountID: id}
		job, status, err := s.repo.Queue(ctx, actorID, id, uuid.NewString(), s.now())
		row.Status = status
		if err != nil {
			row.Status = "error"
			row.ErrorCode = "queue_failed"
			if errors.Is(err, ErrAccountVaultNotFound) {
				row.ErrorCode = "account_not_found"
			}
			if errors.Is(err, ErrVaultRotationBlocked) {
				row.Status = "blocked"
				row.ErrorCode = "previously_completed"
			}
			if errors.Is(err, ErrVaultRotationActive) {
				row.Status = "blocked"
				row.ErrorCode = "owned_by_other_admin"
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
	for index := range result.Rows {
		s.decorateWorker(actorID, result.Rows[index].Job)
	}
	return result, nil
}
func (s *AccountVaultRotationService) Query(ctx context.Context, actorID int64, ids []int64) ([]AccountVaultRotationDTO, error) {
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if !validRotationIDs(ids, 200) {
		return nil, ErrVaultRotationInvalid
	}
	jobs, err := s.repo.Query(ctx, actorID, ids)
	if err != nil {
		return nil, rotationError(err)
	}
	for _, job := range jobs {
		if job.Status == "queued" {
			s.ensureWorker(ctx, actorID)
			break
		}
	}
	result := make([]AccountVaultRotationDTO, 0, len(jobs))
	for _, job := range jobs {
		dto := job.Public()
		s.decorateWorker(actorID, &dto)
		result = append(result, dto)
	}
	return result, nil
}
func (s *AccountVaultRotationService) adminUpdate(ctx context.Context, actorID int64, id string, resume bool) (*AccountVaultRotationDTO, error) {
	if _, err := s.actor(ctx, actorID); err != nil {
		return nil, err
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrVaultRotationInvalid
	}
	job, err := s.repo.Update(ctx, actorID, id, nil, func(job AccountVaultRotationJob, record AccountVaultRecord) (AccountVaultRotationMutation, error) {
		if resume {
			if job.Status != "paused" {
				return AccountVaultRotationMutation{}, ErrVaultRotationConflict
			}
			if job.Phase == "enroll_intent" {
				return AccountVaultRotationMutation{}, ErrVaultRotationManual
			}
			job.Status = "queued"
			if job.Kind == "session" {
				job.Phase = "login"
				job.PendingEncrypted = ""
			}
			job.Progress = "queued"
			job.ErrorCode = ""
		} else {
			if (job.Status != "queued" && job.Status != "paused") || !safeCancel(job.Phase) {
				return AccountVaultRotationMutation{}, ErrVaultRotationManual
			}
			job.Status = "cancelled"
			job.Progress = "cancelled"
			job.PendingEncrypted = ""
			job.ErrorCode = ""
		}
		job.LeaseHash = ""
		job.LeaseExpiresAt = nil
		job.Revision++
		job.UpdatedAt = s.now()
		return AccountVaultRotationMutation{Job: job, Event: job.Status}, nil
	})
	if err != nil {
		return nil, rotationError(err)
	}
	dto := job.Public()
	if resume {
		s.ensureWorker(ctx, actorID)
	}
	s.decorateWorker(actorID, &dto)
	return &dto, nil
}
func (s *AccountVaultRotationService) Resume(ctx context.Context, actorID int64, id string) (*AccountVaultRotationDTO, error) {
	return s.adminUpdate(ctx, actorID, id, true)
}
func (s *AccountVaultRotationService) Cancel(ctx context.Context, actorID int64, id string) (*AccountVaultRotationDTO, error) {
	return s.adminUpdate(ctx, actorID, id, false)
}

type AccountVaultWorkerTokenResult struct {
	Token     string    `json:"token"`
	TokenID   string    `json:"token_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *AccountVaultRotationService) CreateWorkerToken(ctx context.Context, actorID int64) (*AccountVaultWorkerTokenResult, error) {
	user, err := s.actor(ctx, actorID)
	if err != nil {
		return nil, err
	}
	if err = s.ready(ctx); err != nil {
		return nil, err
	}
	token, err := randomRotationToken()
	if err != nil {
		return nil, err
	}
	token = "avw1_" + token
	row := AccountVaultWorkerToken{ID: uuid.NewString(), ActorID: actorID, TokenVersion: resolvedTokenVersion(user), Hash: rotationHash(token), ExpiresAt: s.now().Add(8 * time.Hour)}
	if err = s.repo.CreateToken(ctx, row); err != nil {
		return nil, rotationError(err)
	}
	return &AccountVaultWorkerTokenResult{Token: token, TokenID: row.ID, ExpiresAt: row.ExpiresAt}, nil
}
func (s *AccountVaultRotationService) RevokeWorkerTokens(ctx context.Context, actorID int64) error {
	if _, err := s.actor(ctx, actorID); err != nil {
		return err
	}
	return rotationError(s.repo.RevokeTokens(ctx, actorID))
}
func (s *AccountVaultRotationService) AuthenticateWorker(ctx context.Context, token string) (*AccountVaultWorkerGrant, error) {
	if s == nil || s.repo == nil || len(token) != 48 || !strings.HasPrefix(token, "avw1_") {
		return nil, ErrVaultWorkerUnauthorized
	}
	row, err := s.repo.FindToken(ctx, rotationHash(token))
	if err != nil || row == nil || row.Revoked || !row.ExpiresAt.After(s.now()) {
		return nil, ErrVaultWorkerUnauthorized
	}
	user, err := s.actor(ctx, row.ActorID)
	if err != nil || resolvedTokenVersion(user) != row.TokenVersion {
		return nil, ErrVaultWorkerUnauthorized
	}
	if err = s.ready(ctx); err != nil {
		return nil, err
	}
	return &AccountVaultWorkerGrant{TokenID: row.ID, ActorID: row.ActorID}, nil
}

type AccountVaultRotationWorkerAccount struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type AccountVaultRotationWorkerCheckpoint struct {
	UpstreamID  string `json:"upstream_id"`
	OldFactorID string `json:"old_factor_id"`
	NewFactorID string `json:"new_factor_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
}
type AccountVaultRotationClaim struct {
	Job            *AccountVaultRotationDTO              `json:"job"`
	LeaseToken     string                                `json:"lease_token,omitempty"`
	LeaseExpiresAt *time.Time                            `json:"lease_expires_at,omitempty"`
	Account        *AccountVaultRotationWorkerAccount    `json:"account,omitempty"`
	Checkpoint     *AccountVaultRotationWorkerCheckpoint `json:"checkpoint,omitempty"`
}

func (s *AccountVaultRotationService) Claim(ctx context.Context, grant *AccountVaultWorkerGrant, workerID string) (*AccountVaultRotationClaim, error) {
	if grant == nil || !validOpaque(workerID) || len(workerID) > 128 {
		return nil, ErrVaultRotationInvalid
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	token, err := randomRotationToken()
	if err != nil {
		return nil, err
	}
	job, record, err := s.repo.Claim(ctx, grant.ActorID, rotationHash(token), s.now())
	if err != nil {
		return nil, rotationError(err)
	}
	if job == nil {
		return &AccountVaultRotationClaim{}, nil
	}
	input, err := s.vault.open(*record)
	if err != nil {
		return nil, err
	}
	dto := job.Public()
	result := &AccountVaultRotationClaim{Job: &dto, LeaseToken: token, LeaseExpiresAt: job.LeaseExpiresAt, Account: &AccountVaultRotationWorkerAccount{Email: input.Email, Password: input.Password}}
	if job.Kind != "session" && job.PendingEncrypted != "" {
		pending, err := s.openPending(*job, *record)
		if err != nil {
			return nil, err
		}
		result.Checkpoint = &AccountVaultRotationWorkerCheckpoint{UpstreamID: pending.UpstreamID, OldFactorID: pending.OldFactorID, NewFactorID: pending.NewFactorID, SessionID: pending.SessionID}
	}
	return result, nil
}
func (s *AccountVaultRotationService) fence(token string, revision int64) (*AccountVaultRotationFence, error) {
	if len(token) != 43 || revision <= 0 {
		return nil, ErrVaultRotationInvalid
	}
	return &AccountVaultRotationFence{LeaseHash: rotationHash(token), Revision: revision, Now: s.now()}, nil
}
func (s *AccountVaultRotationService) workerUpdate(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, fn AccountVaultRotationUpdate) (*AccountVaultRotationJob, error) {
	if grant == nil {
		return nil, ErrVaultWorkerUnauthorized
	}
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrVaultRotationInvalid
	}
	fence, err := s.fence(token, revision)
	if err != nil {
		return nil, err
	}
	job, err := s.repo.Update(ctx, grant.ActorID, id, fence, fn)
	return job, rotationError(err)
}

type AccountVaultRotationHeartbeatResult struct {
	Job            AccountVaultRotationDTO `json:"job"`
	LeaseExpiresAt *time.Time              `json:"lease_expires_at"`
}

func (s *AccountVaultRotationService) Heartbeat(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, progress string) (*AccountVaultRotationHeartbeatResult, error) {
	if progress != "" && progress != "awaiting_user" && progress != "awaiting_navigation" && progress != "awaiting_cloudflare" && progress != "awaiting_provider" && progress != "awaiting_authorization" && progress != "working" && progress != "authorizing" && progress != "exchanging" {
		return nil, ErrVaultRotationInvalid
	}
	if grant == nil {
		return nil, ErrVaultWorkerUnauthorized
	}
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrVaultRotationInvalid
	}
	fence, err := s.fence(token, revision)
	if err != nil {
		return nil, err
	}
	fence.AllowStaleRevision = true
	job, err := s.repo.Update(ctx, grant.ActorID, id, fence, func(job AccountVaultRotationJob, _ AccountVaultRecord) (AccountVaultRotationMutation, error) {
		if progress == "authorizing" || progress == "exchanging" {
			if job.Kind != "session" {
				return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
			}
			job.Progress = progress
		}
		expires := s.now().Add(VaultRotationLease)
		job.LeaseExpiresAt = &expires
		job.UpdatedAt = s.now()
		if progress == "awaiting_user" || progress == "awaiting_navigation" || progress == "awaiting_cloudflare" || progress == "awaiting_provider" || progress == "awaiting_authorization" {
			job.Progress = progress
		} else if progress == "working" {
			job.Progress = job.Phase
		}
		return AccountVaultRotationMutation{Job: job}, nil
	})
	if err != nil {
		return nil, rotationError(err)
	}
	return &AccountVaultRotationHeartbeatResult{Job: job.Public(), LeaseExpiresAt: job.LeaseExpiresAt}, nil
}

var rotationPauseCodes = map[string]bool{"login_failed": true, "identity_mismatch": true, "identity_response_empty": true, "identity_response_nested_user": true, "identity_response_nested_data": true, "identity_response_api_error": true, "identity_response_missing_id": true, "identity_response_invalid_id": true, "identity_response_missing_email": true, "identity_response_invalid_email": true, "identity_response_email_array": true, "identity_response_email_object": true, "identity_response_email_number": true, "identity_response_email_boolean": true, "cloudflare_challenge": true, "mfa_state_mismatch": true, "upstream_rejected": true, "upstream_timeout": true, "enrollment_uncertain": true, "activation_uncertain": true, "manual_required": true, "worker_stopped": true, "storage_failed": true, "unsupported_login": true, "network_error": true}

func (s *AccountVaultRotationService) Pause(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, code string) (*AccountVaultRotationDTO, error) {
	if !rotationPauseCodes[code] {
		return nil, ErrVaultRotationInvalid
	}
	job, err := s.workerUpdate(ctx, grant, id, token, revision, func(job AccountVaultRotationJob, _ AccountVaultRecord) (AccountVaultRotationMutation, error) {
		job.Status = "paused"
		job.Progress = "paused"
		job.ErrorCode = code
		job.LeaseHash = ""
		job.LeaseExpiresAt = nil
		job.Revision++
		job.UpdatedAt = s.now()
		return AccountVaultRotationMutation{Job: job, Event: "paused"}, nil
	})
	if err != nil {
		return nil, err
	}
	dto := job.Public()
	return &dto, nil
}
func (s *AccountVaultRotationService) openPending(job AccountVaultRotationJob, record AccountVaultRecord) (AccountVaultRotationPending, error) {
	plaintext, err := s.vault.cipher.DecryptRotation(job.ID, record.VaultID, record.Email, job.PendingEncrypted)
	defer clear(plaintext)
	if err != nil {
		return AccountVaultRotationPending{}, vaultDecryptError()
	}
	var pending AccountVaultRotationPending
	if json.Unmarshal(plaintext, &pending) != nil || pending.Email != record.Email || !validOpaque(pending.UpstreamID) || !validOpaque(pending.OldFactorID) {
		return AccountVaultRotationPending{}, vaultDecryptError()
	}
	return pending, nil
}
func (s *AccountVaultRotationService) sealPending(job AccountVaultRotationJob, record AccountVaultRecord, pending AccountVaultRotationPending) (string, error) {
	plaintext, err := json.Marshal(pending)
	defer clear(plaintext)
	if err != nil {
		return "", vaultDecryptError()
	}
	envelope, err := s.vault.cipher.EncryptRotation(job.ID, record.VaultID, record.Email, plaintext)
	if err != nil {
		return "", vaultDecryptError()
	}
	return envelope, nil
}
func validObservation(identity *AccountVaultRotationIdentity, mfa *AccountVaultRotationMFA, email string) bool {
	if identity == nil || mfa == nil || !validOpaque(identity.ID) || strings.ToLower(strings.TrimSpace(identity.Email)) != email || len(mfa.TOTPFactorIDs) > 20 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range mfa.TOTPFactorIDs {
		if !validOpaque(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return mfa.DefaultFactorID == "" || validOpaque(mfa.DefaultFactorID)
}
func (s *AccountVaultRotationService) Checkpoint(ctx context.Context, grant *AccountVaultWorkerGrant, id string, req AccountVaultRotationCheckpoint) (*AccountVaultRotationCheckpointResult, error) {
	result := &AccountVaultRotationCheckpointResult{}
	job, err := s.workerUpdate(ctx, grant, id, req.LeaseToken, req.Revision, func(job AccountVaultRotationJob, record AccountVaultRecord) (AccountVaultRotationMutation, error) {
		mutation, permit, factor, err := s.transition(job, record, req)
		if err != nil {
			return mutation, err
		}
		result.Permit = permit
		result.FactorID = factor
		return mutation, nil
	})
	if err != nil {
		return nil, err
	}
	result.Job = job.Public()
	return result, nil
}

// transition is a pure state decision apart from authenticated encryption. The
// repository commits its result, row metadata and event in one transaction.
func (s *AccountVaultRotationService) transition(job AccountVaultRotationJob, record AccountVaultRecord, req AccountVaultRotationCheckpoint) (AccountVaultRotationMutation, string, string, error) {
	if job.Kind == "session" {
		return AccountVaultRotationMutation{}, "", "", ErrVaultRotationInvalid
	}
	invalid := func() (AccountVaultRotationMutation, string, string, error) {
		return AccountVaultRotationMutation{}, "", "", ErrVaultRotationConflict
	}
	if job.Status != "running" || rotationHash(record.EncryptedData) != job.BaseCipherHash {
		return invalid()
	}
	var pending AccountVaultRotationPending
	if job.Phase != "login" {
		var err error
		pending, err = s.openPending(job, record)
		if err != nil {
			return AccountVaultRotationMutation{}, "", "", err
		}
	}
	observation := req.Action == "prepared" || req.Action == "disabled" || req.Action == "verify"
	if observation {
		if req.Enrollment != nil || !validObservation(req.Identity, req.MFA, record.Email) {
			return invalid()
		}
		if job.Phase != "login" && req.Identity.ID != pending.UpstreamID {
			return invalid()
		}
	} else if req.Identity != nil || req.MFA != nil {
		return invalid()
	}
	if req.Action != "enrolled" && req.Enrollment != nil {
		return invalid()
	}
	permit, factor, event := "", "", req.Action
	mutation := AccountVaultRotationMutation{}
	switch req.Action {
	case "prepared":
		if job.Phase != "login" || !req.MFA.Enabled || !req.MFA.EnabledV2 || len(req.MFA.TOTPFactorIDs) != 1 || req.MFA.DefaultFactorID != req.MFA.TOTPFactorIDs[0] {
			return invalid()
		}
		pending = AccountVaultRotationPending{Email: record.Email, UpstreamID: req.Identity.ID, OldFactorID: req.MFA.TOTPFactorIDs[0]}
		job.SubjectHash = rotationHash(VaultRotationProvider + "\x00" + pending.UpstreamID)
		job.Phase = "prepared"
	case "disable":
		if job.Phase != "prepared" {
			return invalid()
		}
		job.Phase = "disable_intent"
		permit = "disable"
		factor = pending.OldFactorID
	case "disabled":
		if job.Phase != "disable_intent" || req.MFA.Enabled || req.MFA.EnabledV2 || len(req.MFA.TOTPFactorIDs) != 0 || req.MFA.DefaultFactorID != "" {
			return invalid()
		}
		job.Phase = "disabled"
	case "enroll":
		if job.Phase != "disabled" {
			return invalid()
		}
		job.Phase = "enroll_intent"
		permit = "enroll"
	case "enrolled":
		if job.Phase != "enroll_intent" || req.Enrollment == nil || req.Enrollment.FactorType != "totp" || !validOpaque(req.Enrollment.SessionID) || !validOpaque(req.Enrollment.FactorID) || req.Enrollment.FactorID == pending.OldFactorID {
			return invalid()
		}
		normalized, err := accountvault.Normalize(accountvault.Input{Email: record.Email, Secret: req.Enrollment.Secret, Algorithm: "SHA1", Digits: 6, Period: 30})
		if err != nil {
			return invalid()
		}
		pending.Secret = normalized.Secret
		pending.SessionID = req.Enrollment.SessionID
		pending.NewFactorID = req.Enrollment.FactorID
		job.Phase = "enrolled"
	case "activate":
		if job.Phase != "enrolled" || pending.Secret == "" || pending.SessionID == "" || pending.NewFactorID == "" {
			return invalid()
		}
		job.Phase = "activate_intent"
		permit = "activate"
	case "verify":
		if (job.Phase != "enrolled" && job.Phase != "activate_intent") || pending.Secret == "" || pending.NewFactorID == "" || pending.NewFactorID == pending.OldFactorID || !req.MFA.Enabled || !req.MFA.EnabledV2 || len(req.MFA.TOTPFactorIDs) != 1 || req.MFA.TOTPFactorIDs[0] != pending.NewFactorID || req.MFA.DefaultFactorID != pending.NewFactorID {
			return invalid()
		}
		input, err := s.vault.open(record)
		if err != nil {
			return AccountVaultRotationMutation{}, "", "", err
		}
		input.Secret = pending.Secret
		input.Algorithm = "SHA1"
		input.Digits = 6
		input.Period = 30
		encrypted, err := s.vault.cipher.Encrypt(record.VaultID, input)
		if err != nil {
			return AccountVaultRotationMutation{}, "", "", vaultDecryptError()
		}
		mutation.NewEncryptedData = encrypted
		mutation.Complete = true
		job.PendingEncrypted = ""
		job.Status = "completed"
		job.Phase = "completed"
		job.LeaseHash = ""
		job.LeaseExpiresAt = nil
		now := s.now()
		job.CompletedAt = &now
		event = "completed"
	default:
		return AccountVaultRotationMutation{}, "", "", ErrVaultRotationInvalid
	}
	if !mutation.Complete {
		encrypted, err := s.sealPending(job, record, pending)
		if err != nil {
			return AccountVaultRotationMutation{}, "", "", err
		}
		job.PendingEncrypted = encrypted
	}
	job.Revision++
	job.UpdatedAt = s.now()
	job.Progress = job.Phase
	job.ErrorCode = ""
	mutation.Job = job
	mutation.Event = event
	return mutation, permit, factor, nil
}

type AccountVaultRotationCode struct {
	accountvault.Code
	SessionID string `json:"session_id,omitempty"`
	FactorID  string `json:"factor_id,omitempty"`
}

func (s *AccountVaultRotationService) Code(ctx context.Context, grant *AccountVaultWorkerGrant, id, token string, revision int64, activation bool) (*AccountVaultRotationCode, error) {
	result := &AccountVaultRotationCode{}
	_, err := s.workerUpdate(ctx, grant, id, token, revision, func(job AccountVaultRotationJob, record AccountVaultRecord) (AccountVaultRotationMutation, error) {
		if job.Kind == "session" && activation {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		var input accountvault.Input
		if activation {
			if job.Phase != "activate_intent" {
				return AccountVaultRotationMutation{}, ErrVaultRotationConflict
			}
			pending, err := s.openPending(job, record)
			if err != nil {
				return AccountVaultRotationMutation{}, err
			}
			if pending.Secret == "" || pending.SessionID == "" || pending.NewFactorID == "" {
				return AccountVaultRotationMutation{}, ErrVaultRotationManual
			}
			input = accountvault.Input{Email: record.Email, Secret: pending.Secret, Algorithm: "SHA1", Digits: 6, Period: 30}
			result.SessionID = pending.SessionID
			result.FactorID = pending.NewFactorID
		} else {
			switch job.Phase {
			case "login", "prepared", "disable_intent":
				var err error
				input, err = s.vault.open(record)
				if err != nil {
					return AccountVaultRotationMutation{}, err
				}
			case "enrolled", "activate_intent":
				pending, err := s.openPending(job, record)
				if err != nil {
					return AccountVaultRotationMutation{}, err
				}
				if pending.Secret == "" || pending.NewFactorID == "" {
					return AccountVaultRotationMutation{}, ErrVaultRotationManual
				}
				input = accountvault.Input{Email: record.Email, Secret: pending.Secret, Algorithm: "SHA1", Digits: 6, Period: 30}
			default:
				return AccountVaultRotationMutation{}, ErrVaultRotationManual
			}
		}
		code, err := accountvault.GenerateCode(input, s.now())
		if err != nil {
			return AccountVaultRotationMutation{}, ErrVaultRotationInvalid
		}
		result.Code = code
		return AccountVaultRotationMutation{Job: job}, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
