package service

import (
	"context"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var (
	ErrAccountVaultNotFound    = infraerrors.NotFound("ACCOUNT_VAULT_NOT_FOUND", "账号不存在")
	ErrAccountVaultUnavailable = infraerrors.ServiceUnavailable("ACCOUNT_VAULT_KEY_REQUIRED", "账号库尚未配置固定加密密钥，请设置 ACCOUNT_VAULT_ENCRYPTION_KEY 后重启")
	ErrAccountVaultKeyMismatch = infraerrors.ServiceUnavailable("ACCOUNT_VAULT_KEY_MISMATCH", "加密密钥与账号库已绑定的密钥不一致，请恢复原密钥")
)

// AccountVaultRecord contains public metadata and one encrypted payload. Passwords
// and external-account TOTP seeds must never be stored in gateway credentials.
type AccountVaultRecord struct {
	ID                  int64
	VaultID             string
	Email               string
	Issuer              string
	GroupName           string
	HasPassword         bool
	Algorithm           string
	Digits              int
	Period              int
	EncryptedData       string
	CreatedBy           int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
	RotationState       string
	RotationPhase       string
	RotationCompletedAt *time.Time
}

type AccountVaultRepository interface {
	// EnsureKey atomically binds the database to its initial non-secret key
	// fingerprint and rejects instances configured with a different master key.
	EnsureKey(ctx context.Context, fingerprint string) error
	List(ctx context.Context, page, pageSize int, search string) ([]AccountVaultRecord, int64, error)
	GetByID(ctx context.Context, id int64) (*AccountVaultRecord, error)
	GetByEmail(ctx context.Context, email string) (*AccountVaultRecord, error)
	GetByIDs(ctx context.Context, ids []int64) ([]AccountVaultRecord, error)
	// Create atomically preserves an existing email. A successful insert fills ID
	// and timestamps; false means a duplicate and never updates encrypted fields.
	Create(ctx context.Context, record *AccountVaultRecord) (bool, error)
	Delete(ctx context.Context, id int64) error
}

type AccountVaultSummary struct {
	ID                  int64      `json:"id"`
	Email               string     `json:"email"`
	Issuer              string     `json:"issuer"`
	GroupName           string     `json:"group_name"`
	HasPassword         bool       `json:"has_password"`
	HasTOTP             bool       `json:"has_totp"`
	Algorithm           string     `json:"algorithm"`
	Digits              int        `json:"digits"`
	Period              int        `json:"period"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	RotationState       string     `json:"rotation_state"`
	RotationPhase       string     `json:"rotation_phase"`
	RotationCompletedAt *time.Time `json:"rotation_completed_at,omitempty"`
}

type AccountVaultGroup struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type AccountVaultGroupingRepository interface {
	ListByGroup(context.Context, int, int, string, string) ([]AccountVaultRecord, int64, error)
	Groups(context.Context) ([]AccountVaultGroup, error)
	AssignGroup(context.Context, []int64, string) error
}
