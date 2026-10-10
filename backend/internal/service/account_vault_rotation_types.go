package service

import (
	"context"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"time"
)

var (
	ErrVaultRotationConflict   = infraerrors.Conflict("ACCOUNT_VAULT_ROTATION_CONFLICT", "换绑状态已变化，请刷新后重试")
	ErrVaultRotationActive     = infraerrors.Conflict("ACCOUNT_VAULT_ROTATION_ACTIVE", "账号存在未完成的换绑任务，不能删除")
	ErrVaultRotationBlocked    = infraerrors.Conflict("ACCOUNT_VAULT_ROTATION_PREVIOUSLY_COMPLETED", "此账号曾完成换绑，请人工核对，不能再次自动关闭 2FA")
	ErrVaultRotationManual     = infraerrors.Conflict("ACCOUNT_VAULT_ROTATION_MANUAL_REQUIRED", "远端状态不确定，请保留当前凭证并人工核对")
	ErrVaultRotationNotFound   = infraerrors.NotFound("ACCOUNT_VAULT_ROTATION_NOT_FOUND", "换绑任务不存在")
	ErrVaultWorkerUnauthorized = infraerrors.Unauthorized("ACCOUNT_VAULT_WORKER_UNAUTHORIZED", "浏览器助手连接码无效、已撤销或已过期")
	ErrVaultRotationInvalid    = infraerrors.BadRequest("ACCOUNT_VAULT_ROTATION_INVALID", "换绑请求格式或参数无效")
)

const VaultRotationProvider = "chatgpt"
const VaultRotationLease = 90 * time.Second
const VaultRotationDefaultConcurrency = 2
const VaultRotationMaxConcurrency = 4

// RotationJob is a persistence record. Only Public returns a client-safe view.
type AccountVaultRotationJob struct {
	Kind             string
	GatewayAccountID int64
	ID               string
	AccountID        int64
	ActorID          int64
	Provider         string
	Status           string
	Phase            string
	Revision         int64
	Progress         string
	ErrorCode        string
	PendingEncrypted string
	SubjectHash      string
	BaseCipherHash   string
	LeaseHash        string
	LeaseExpiresAt   *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CompletedAt      *time.Time
}

type AccountVaultRotationDTO struct {
	Kind                string     `json:"kind,omitempty"`
	GatewayAccountID    int64      `json:"gateway_account_id,omitempty"`
	CredentialExpiresAt string     `json:"credential_expires_at,omitempty"`
	ID                  string     `json:"id"`
	AccountID           int64      `json:"account_id"`
	Status              string     `json:"status"`
	Phase               string     `json:"phase"`
	Revision            int64      `json:"revision"`
	Progress            string     `json:"progress"`
	Message             string     `json:"message"`
	WorkerStatus        string     `json:"worker_status,omitempty"`
	WorkerErrorCode     string     `json:"worker_error_code,omitempty"`
	ErrorCode           string     `json:"error_code,omitempty"`
	CanCancel           bool       `json:"can_cancel"`
	CanResume           bool       `json:"can_resume"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
}

type AccountVaultRotationQueueRow struct {
	AccountID int64                    `json:"account_id"`
	Status    string                   `json:"status"`
	Job       *AccountVaultRotationDTO `json:"job,omitempty"`
	ErrorCode string                   `json:"error_code,omitempty"`
}
type AccountVaultRotationQueueResult struct {
	Rows []AccountVaultRotationQueueRow `json:"rows"`
}
type AccountVaultWorkerToken struct {
	ID           string
	ActorID      int64
	TokenVersion int64
	Hash         string
	ExpiresAt    time.Time
	Revoked      bool
}
type AccountVaultWorkerGrant struct {
	TokenID string
	ActorID int64
}
type AccountVaultRotationFence struct {
	Revision           int64
	LeaseHash          string
	Now                time.Time
	AllowStaleRevision bool
}
type AccountVaultRotationMutation struct {
	Job              AccountVaultRotationJob
	Event            string
	NewEncryptedData string
	// Completion inserts both unique provider/email and provider/subject ledger.
	Complete bool
}

// The callback executes with the account and job rows locked, in that order.
// Repositories only receive opaque encrypted payloads; services own all secrets.
type AccountVaultRotationUpdate func(AccountVaultRotationJob, AccountVaultRecord) (AccountVaultRotationMutation, error)
type AccountVaultRotationRepository interface {
	QueueSession(context.Context, int64, int64, string, time.Time) (*AccountVaultRotationJob, string, error)
	QuerySessions(context.Context, int64, []int64) ([]AccountVaultRotationJob, error)
	SetConcurrency(context.Context, int64, int) error
	Queue(context.Context, int64, int64, string, time.Time) (*AccountVaultRotationJob, string, error)
	Query(context.Context, int64, []int64) ([]AccountVaultRotationJob, error)
	Claim(context.Context, int64, string, time.Time) (*AccountVaultRotationJob, *AccountVaultRecord, error)
	Update(context.Context, int64, string, *AccountVaultRotationFence, AccountVaultRotationUpdate) (*AccountVaultRotationJob, error)
	CreateToken(context.Context, AccountVaultWorkerToken) error
	FindToken(context.Context, string) (*AccountVaultWorkerToken, error)
	RevokeTokens(context.Context, int64) error
}

type AccountVaultRotationIdentity struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}
type AccountVaultRotationMFA struct {
	Enabled         bool     `json:"enabled"`
	EnabledV2       bool     `json:"enabled_v2"`
	DefaultFactorID string   `json:"default_factor_id"`
	TOTPFactorIDs   []string `json:"totp_factor_ids"`
}
type AccountVaultRotationEnrollment struct {
	Secret     string `json:"secret"`
	SessionID  string `json:"session_id"`
	FactorID   string `json:"factor_id"`
	FactorType string `json:"factor_type"`
}
type AccountVaultRotationCheckpoint struct {
	LeaseToken string                          `json:"lease_token"`
	Revision   int64                           `json:"revision"`
	Action     string                          `json:"action"`
	Identity   *AccountVaultRotationIdentity   `json:"identity,omitempty"`
	MFA        *AccountVaultRotationMFA        `json:"mfa,omitempty"`
	Enrollment *AccountVaultRotationEnrollment `json:"enrollment,omitempty"`
}
type AccountVaultRotationCheckpointResult struct {
	Job      AccountVaultRotationDTO `json:"job"`
	Permit   string                  `json:"permit,omitempty"`
	FactorID string                  `json:"factor_id,omitempty"`
}
type AccountVaultRotationPending struct {
	Email       string `json:"email"`
	UpstreamID  string `json:"upstream_id"`
	OldFactorID string `json:"old_factor_id"`
	NewFactorID string `json:"new_factor_id,omitempty"`
	Secret      string `json:"secret,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
}
