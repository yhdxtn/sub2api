package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/accountvault"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/google/uuid"
)

const (
	AccountVaultMaxImportRows  = 500
	AccountVaultMaxImportBytes = 2 * 1024 * 1024
	AccountVaultMaxCodeRows    = 200
)

type AccountVaultService struct {
	repo        AccountVaultRepository
	cipher      *accountvault.Cipher
	now         func() time.Time
	importSlots chan struct{}
	keyMu       sync.Mutex
	keyVerified bool
}

func NewAccountVaultService(repo AccountVaultRepository, cfg *config.Config) *AccountVaultService {
	s := &AccountVaultService{repo: repo, now: time.Now, importSlots: make(chan struct{}, 2)}
	if cfg != nil && cfg.AccountVault.EncryptionKey != "" {
		// A malformed or missing key disables this optional module. It must not
		// replace a configured key or stop the original gateway from starting.
		s.cipher, _ = accountvault.NewCipher(cfg.AccountVault.EncryptionKey)
	}
	return s
}

type AccountVaultStatus struct {
	Configured     bool   `json:"configured"`
	Ready          bool   `json:"ready"`
	MaxImportRows  int    `json:"max_import_rows"`
	MaxImportBytes int    `json:"max_import_bytes"`
	Message        string `json:"message,omitempty"`
}

func (s *AccountVaultService) Status(ctx context.Context) AccountVaultStatus {
	status := AccountVaultStatus{Configured: s.cipher != nil, MaxImportRows: AccountVaultMaxImportRows, MaxImportBytes: AccountVaultMaxImportBytes}
	if err := s.checkKey(ctx); err != nil {
		status.Message = "账号库需要固定的 32 字节 Base64 加密密钥；如已有数据，请使用原密钥并检查数据库连接"
		return status
	}
	status.Ready = true
	return status
}

func (s *AccountVaultService) requireCipher() error {
	if s == nil || s.cipher == nil {
		return ErrAccountVaultUnavailable
	}
	return nil
}

// checkKey verifies existing ciphertext and atomically binds the database to one
// key, including when different instances race on an empty vault. Cache success
// only: missing migrations, transient storage failures and wrong keys may retry.
func (s *AccountVaultService) checkKey(ctx context.Context) error {
	if err := s.requireCipher(); err != nil {
		return err
	}
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.keyVerified {
		return nil
	}
	rows, _, err := s.repo.List(ctx, 1, 1, "")
	if err != nil {
		return vaultStorageError()
	}
	if len(rows) > 0 {
		if _, err = s.open(rows[0]); err != nil {
			return err
		}
	}
	if err = s.repo.EnsureKey(ctx, s.cipher.KeyFingerprint()); err != nil {
		if errors.Is(err, ErrAccountVaultKeyMismatch) {
			return err
		}
		return vaultStorageError()
	}
	s.keyVerified = true
	return nil
}

func vaultStorageError() error {
	return infraerrors.InternalServer("ACCOUNT_VAULT_STORAGE_FAILED", "账号库操作失败，请检查数据库连接")
}

func vaultDecryptError() error {
	return infraerrors.ServiceUnavailable("ACCOUNT_VAULT_DECRYPT_FAILED", "账号凭证无法解密，请检查原加密密钥和数据完整性")
}

func (s *AccountVaultService) open(record AccountVaultRecord) (accountvault.Input, error) {
	if err := s.requireCipher(); err != nil {
		return accountvault.Input{}, err
	}
	input, err := s.cipher.Decrypt(record.VaultID, record.Email, record.EncryptedData)
	if err != nil {
		return accountvault.Input{}, vaultDecryptError()
	}
	if input.Email != record.Email || input.Issuer != record.Issuer || input.Algorithm != record.Algorithm ||
		input.Digits != record.Digits || input.Period != record.Period || (input.Password != "") != record.HasPassword {
		return accountvault.Input{}, vaultDecryptError()
	}
	return input, nil
}

func vaultSummary(record AccountVaultRecord) AccountVaultSummary {
	return AccountVaultSummary{ID: record.ID, Email: record.Email, Issuer: record.Issuer, GroupName: record.GroupName, HasPassword: record.HasPassword,
		HasTOTP: true, Algorithm: record.Algorithm, Digits: record.Digits, Period: record.Period,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		RotationState: record.RotationState, RotationPhase: record.RotationPhase, RotationCompletedAt: record.RotationCompletedAt}
}

// The active ciphertext remains recoverable until the replacement is confirmed.
// Once a remote change may have started, it must no longer look like a valid
// current TOTP in the ordinary list or explicit Secret endpoint.
func vaultRotationBlocksTOTP(record AccountVaultRecord) bool {
	switch record.RotationState {
	case "completed":
		return record.RotationCompletedAt == nil || record.RotationPhase != "completed"
	case "required", "":
		return record.RotationPhase != ""
	case "cancelled":
		return record.RotationPhase != "" && record.RotationPhase != "login" && record.RotationPhase != "prepared"
	case "queued", "running", "paused":
		return record.RotationPhase != "login" && record.RotationPhase != "prepared"
	default:
		return true
	}
}

func vaultRotationPendingError() error {
	return infraerrors.Conflict("ACCOUNT_VAULT_ROTATION_PENDING", "此账号换绑尚未确认完成，请在换绑进度中继续处理")
}

func (s *AccountVaultService) List(ctx context.Context, page, pageSize int, search string, group ...string) ([]AccountVaultSummary, int64, error) {
	if err := s.checkKey(ctx); err != nil {
		return nil, 0, err
	}
	if page < 1 || page > 1000000 || pageSize < 1 || pageSize > 100 || len(search) > 320 {
		return nil, 0, infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_PAGE", "分页或搜索参数无效")
	}
	var rows []AccountVaultRecord
	var total int64
	var err error
	if len(group) > 0 {
		name, validationErr := normalizeVaultGroup(group[0])
		if validationErr != nil {
			return nil, 0, validationErr
		}
		repo, ok := s.repo.(AccountVaultGroupingRepository)
		if !ok {
			return nil, 0, vaultStorageError()
		}
		rows, total, err = repo.ListByGroup(ctx, page, pageSize, strings.TrimSpace(search), name)
	} else {
		rows, total, err = s.repo.List(ctx, page, pageSize, strings.TrimSpace(search))
	}
	if err != nil {
		return nil, 0, vaultStorageError()
	}
	items := make([]AccountVaultSummary, 0, len(rows))
	for _, row := range rows {
		items = append(items, vaultSummary(row))
	}
	return items, total, nil
}

type AccountVaultImportRequest struct {
	Content        string               `json:"content"`
	Items          []accountvault.Input `json:"items"`
	DryRun         bool                 `json:"dry_run"`
	RotateOnImport bool                 `json:"rotate_on_import"`
}

type AccountVaultImportRow struct {
	Line        int    `json:"line"`
	Email       string `json:"email,omitempty"`
	Status      string `json:"status"`
	ID          int64  `json:"id,omitempty"`
	Message     string `json:"message,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	Digits      int    `json:"digits,omitempty"`
	Period      int    `json:"period,omitempty"`
	HasPassword bool   `json:"has_password,omitempty"`
}

type AccountVaultImportResult struct {
	Total         int                              `json:"total"`
	Created       int                              `json:"created"`
	Duplicate     int                              `json:"duplicate"`
	Failed        int                              `json:"failed"`
	Ignored       int                              `json:"ignored"`
	Rows          []AccountVaultImportRow          `json:"rows"`
	Rotation      *AccountVaultRotationQueueResult `json:"rotation,omitempty"`
	RotationError string                           `json:"rotation_error,omitempty"`
}

func (s *AccountVaultService) Import(ctx context.Context, actorID int64, request AccountVaultImportRequest) (*AccountVaultImportResult, error) {
	if err := s.checkKey(ctx); err != nil {
		return nil, err
	}
	select {
	case s.importSlots <- struct{}{}:
		defer func() { <-s.importSlots }()
	default:
		return nil, infraerrors.TooManyRequests("ACCOUNT_VAULT_IMPORT_BUSY", "正在处理其他导入，请稍后重试")
	}
	if (request.Content == "") == (len(request.Items) == 0) || len(request.Content) > AccountVaultMaxImportBytes || len(request.Items) > AccountVaultMaxImportRows {
		return nil, infraerrors.BadRequest("ACCOUNT_VAULT_IMPORT_INVALID", "请选择一种导入内容，每批最多 500 条、文本最多 2 MiB")
	}
	var parsed accountvault.ParseResult
	if request.Content != "" {
		var err error
		parsed, err = accountvault.ParseContent(request.Content)
		if err != nil {
			return nil, infraerrors.BadRequest("ACCOUNT_VAULT_IMPORT_INVALID", "导入内容为空、格式无效或超过 500 条限制")
		}
	} else {
		for i, item := range request.Items {
			input, err := accountvault.Normalize(item)
			row := accountvault.ParsedRow{Line: i + 1}
			if err != nil {
				row.Error = err.Error()
			} else {
				row.Input = &input
			}
			parsed.Rows = append(parsed.Rows, row)
		}
	}
	result := &AccountVaultImportResult{Total: len(parsed.Rows), Ignored: parsed.Ignored, Rows: make([]AccountVaultImportRow, 0, len(parsed.Rows))}
	seen := make(map[string]bool, len(parsed.Rows))
	for _, parsedRow := range parsed.Rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := AccountVaultImportRow{Line: parsedRow.Line, Status: "error"}
		if parsedRow.Input == nil {
			row.Message = parsedRow.Error
			if row.Message == "" {
				row.Message = "这一行格式无效"
			}
			result.Failed++
			result.Rows = append(result.Rows, row)
			continue
		}
		input := *parsedRow.Input
		row.Email, row.Issuer, row.Algorithm = input.Email, input.Issuer, input.Algorithm
		row.Digits, row.Period, row.HasPassword = input.Digits, input.Period, input.Password != ""
		if seen[input.Email] {
			row.Status, row.Message = "duplicate", "本批次已有相同邮箱，已跳过"
			result.Duplicate++
			result.Rows = append(result.Rows, row)
			continue
		}
		seen[input.Email] = true
		existing, err := s.repo.GetByEmail(ctx, input.Email)
		if err == nil {
			row.ID, row.Status, row.Message = existing.ID, "duplicate", "邮箱已存在，保留原密码和 2FA"
			result.Duplicate++
			result.Rows = append(result.Rows, row)
			continue
		}
		if !errors.Is(err, ErrAccountVaultNotFound) {
			row.Message = "读取账号失败，请重试"
			result.Failed++
			result.Rows = append(result.Rows, row)
			continue
		}
		if request.DryRun {
			row.Status = "ready"
			result.Rows = append(result.Rows, row)
			continue
		}
		record := &AccountVaultRecord{VaultID: uuid.NewString(), Email: input.Email, Issuer: input.Issuer, HasPassword: input.Password != "",
			Algorithm: input.Algorithm, Digits: input.Digits, Period: input.Period, CreatedBy: actorID}
		record.EncryptedData, err = s.cipher.Encrypt(record.VaultID, input)
		if err != nil {
			row.Message = "凭证加密失败，未保存"
			result.Failed++
			result.Rows = append(result.Rows, row)
			continue
		}
		created, err := s.repo.Create(ctx, record)
		if err != nil {
			row.Message = "保存失败，请重试"
			result.Failed++
		} else if !created {
			row.Status, row.Message = "duplicate", "邮箱已存在，保留原密码和 2FA"
			result.Duplicate++
		} else {
			row.ID, row.Status = record.ID, "created"
			result.Created++
		}
		result.Rows = append(result.Rows, row)
	}
	return result, nil
}

func (s *AccountVaultService) credential(ctx context.Context, id int64, requireCurrentTOTP bool) (accountvault.Input, error) {
	if err := s.checkKey(ctx); err != nil {
		return accountvault.Input{}, err
	}
	if id <= 0 {
		return accountvault.Input{}, ErrAccountVaultNotFound
	}
	record, err := s.repo.GetByID(ctx, id)
	if errors.Is(err, ErrAccountVaultNotFound) {
		return accountvault.Input{}, err
	}
	if err != nil {
		return accountvault.Input{}, vaultStorageError()
	}
	if requireCurrentTOTP && vaultRotationBlocksTOTP(*record) {
		return accountvault.Input{}, vaultRotationPendingError()
	}
	return s.open(*record)
}

func (s *AccountVaultService) Password(ctx context.Context, id int64) (string, error) {
	input, err := s.credential(ctx, id, false)
	if err != nil {
		return "", err
	}
	if input.Password == "" {
		return "", infraerrors.BadRequest("ACCOUNT_VAULT_NO_PASSWORD", "此账号未保存密码")
	}
	return input.Password, nil
}

func (s *AccountVaultService) Secret(ctx context.Context, id int64) (string, error) {
	input, err := s.credential(ctx, id, true)
	if err != nil {
		return "", err
	}
	return input.Secret, nil
}

// ExportText reads each complete encrypted record in one database query. It
// returns no partial batch or stale seed when a rotation has changed remotely.
func (s *AccountVaultService) ExportText(ctx context.Context, ids []int64) (string, error) {
	if err := s.checkKey(ctx); err != nil {
		return "", err
	}
	if len(ids) == 0 || len(ids) > AccountVaultMaxCodeRows {
		return "", infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_IDS", "每次最多复制 200 个账号")
	}
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return "", infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_IDS", "账号编号无效或重复")
		}
		seen[id] = true
	}
	records, err := s.repo.GetByIDs(ctx, ids)
	if err != nil {
		return "", vaultStorageError()
	}
	byID := make(map[int64]AccountVaultRecord, len(records))
	for _, record := range records {
		byID[record.ID] = record
	}
	lines := make([]string, 0, len(ids))
	for _, id := range ids {
		record, found := byID[id]
		if !found {
			return "", ErrAccountVaultNotFound
		}
		if vaultRotationBlocksTOTP(record) {
			return "", vaultRotationPendingError()
		}
		input, err := s.open(record)
		if err != nil {
			return "", err
		}
		if strings.ContainsAny(input.Password, "\r\n") {
			return "", infraerrors.BadRequest("ACCOUNT_VAULT_TEXT_FORMAT_UNAVAILABLE", "密码包含换行，无法按每行一个账号复制")
		}
		line := input.Email + "----" + input.Password + "----" + input.Secret
		if input.Note != "" {
			line += "----" + input.Note
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"), nil
}

type AccountVaultCode struct {
	ID         int64  `json:"id"`
	Code       string `json:"code,omitempty"`
	Remaining  int    `json:"remaining,omitempty"`
	Period     int    `json:"period,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	ServerTime int64  `json:"server_time,omitempty"`
	Error      string `json:"error,omitempty"`
}

type AccountVaultCodeResult struct {
	Items      []AccountVaultCode `json:"items"`
	ServerTime int64              `json:"server_time"`
}

func (s *AccountVaultService) Codes(ctx context.Context, ids []int64) (*AccountVaultCodeResult, error) {
	if err := s.checkKey(ctx); err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(ids) > AccountVaultMaxCodeRows {
		return nil, infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_IDS", "每次最多读取 200 个账号验证码")
	}
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return nil, infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_IDS", "账号编号无效或重复")
		}
		seen[id] = true
	}
	records, err := s.repo.GetByIDs(ctx, ids)
	if err != nil {
		return nil, vaultStorageError()
	}
	byID := make(map[int64]AccountVaultRecord, len(records))
	for _, record := range records {
		byID[record.ID] = record
	}
	now := s.now()
	result := &AccountVaultCodeResult{Items: make([]AccountVaultCode, 0, len(ids)), ServerTime: now.UnixMilli()}
	for _, id := range ids {
		row := AccountVaultCode{ID: id}
		record, found := byID[id]
		if !found {
			row.Error = "账号不存在"
			result.Items = append(result.Items, row)
			continue
		}
		if vaultRotationBlocksTOTP(record) {
			row.Error = "换绑尚未确认完成，当前验证码已暂停显示"
			result.Items = append(result.Items, row)
			continue
		}
		input, err := s.open(record)
		if err != nil {
			row.Error = "凭证无法解密，请检查加密密钥"
			result.Items = append(result.Items, row)
			continue
		}
		code, err := accountvault.GenerateCode(input, now)
		if err != nil {
			row.Error = "验证码生成失败"
			result.Items = append(result.Items, row)
			continue
		}
		row.Code, row.Remaining, row.Period = code.Code, code.Remaining, code.Period
		row.ExpiresAt, row.ServerTime = code.ExpiresAt, code.ServerTime
		result.Items = append(result.Items, row)
	}
	return result, nil
}

func (s *AccountVaultService) Delete(ctx context.Context, id int64) error {
	if err := s.checkKey(ctx); err != nil {
		return err
	}
	if id <= 0 {
		return ErrAccountVaultNotFound
	}
	err := s.repo.Delete(ctx, id)
	if errors.Is(err, ErrAccountVaultNotFound) || errors.Is(err, ErrVaultRotationActive) {
		return err
	}
	if err != nil {
		return vaultStorageError()
	}
	return nil
}
