package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

const accountVaultMaxBatchSize = 200

const accountVaultColumns = `id, vault_id, email, issuer, has_password, algorithm,
digits, period, encrypted_data, created_by, created_at, updated_at, rotation_state, rotation_phase, rotation_completed_at, group_name`

// accountVaultRepository stores metadata and opaque ciphertext only. Encryption,
// decryption and administrator authorization belong to the service and routes.
type accountVaultRepository struct {
	db *sql.DB
}

var _ service.AccountVaultRepository = (*accountVaultRepository)(nil)
var _ service.AccountVaultGroupingRepository = (*accountVaultRepository)(nil)

func NewAccountVaultRepository(db *sql.DB) service.AccountVaultRepository {
	return &accountVaultRepository{db: db}
}

func (r *accountVaultRepository) ready() error {
	if r == nil || r.db == nil {
		return errors.New("account vault database unavailable")
	}
	return nil
}

// EnsureKey atomically binds this database to its first configured vault key.
// The no-op update locks and returns the existing singleton row even when two
// processes race on an empty database; it never replaces its fingerprint.
func (r *accountVaultRepository) EnsureKey(ctx context.Context, fingerprint string) error {
	if err := r.ready(); err != nil {
		return err
	}
	if len(fingerprint) != 64 || strings.IndexFunc(fingerprint, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f')
	}) >= 0 {
		return errors.New("account vault key fingerprint must be 64 lowercase hexadecimal characters")
	}
	const query = `INSERT INTO account_vault_metadata (id, key_fingerprint)
		VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id
		RETURNING key_fingerprint`
	var stored string
	if err := r.db.QueryRowContext(ctx, query, fingerprint).Scan(&stored); err != nil {
		return fmt.Errorf("verify account vault key binding: %w", err)
	}
	if stored != fingerprint {
		return service.ErrAccountVaultKeyMismatch
	}
	return nil
}

func normalizeAccountVaultEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// accountVaultSearchPattern treats wildcard characters as ordinary input.
func accountVaultSearchPattern(search string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search)
	return "%" + escaped + "%"
}

func (r *accountVaultRepository) List(ctx context.Context, page, pageSize int, search string) ([]service.AccountVaultRecord, int64, error) {
	return r.list(ctx, page, pageSize, search, nil)
}

func (r *accountVaultRepository) ListByGroup(ctx context.Context, page, pageSize int, search, group string) ([]service.AccountVaultRecord, int64, error) {
	return r.list(ctx, page, pageSize, search, &group)
}

func (r *accountVaultRepository) list(ctx context.Context, page, pageSize int, search string, group *string) ([]service.AccountVaultRecord, int64, error) {
	if err := r.ready(); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	} else if pageSize > accountVaultMaxBatchSize {
		pageSize = accountVaultMaxBatchSize
	}
	if int64(page-1) > int64(1<<63-1)/int64(pageSize) {
		return nil, 0, errors.New("account vault pagination is out of range")
	}
	offset := int64(page-1) * int64(pageSize)

	where := ""
	args := make([]any, 0, 3)
	if search = strings.TrimSpace(search); search != "" {
		where = ` WHERE (email ILIKE $1 ESCAPE '\' OR issuer ILIKE $1 ESCAPE '\')`
		args = append(args, accountVaultSearchPattern(search))
	}
	if group != nil {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		args = append(args, *group)
		where += fmt.Sprintf("group_name = $%d", len(args))
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_vault`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count account vault records: %w", err)
	}

	query := `SELECT ` + accountVaultColumns + ` FROM account_vault` + where +
		fmt.Sprintf(" ORDER BY id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, pageSize, offset)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list account vault records: %w", err)
	}
	defer rows.Close()
	records, err := scanAccountVaultRows(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("list account vault records: %w", err)
	}
	return records, total, nil
}

func (r *accountVaultRepository) GetByID(ctx context.Context, id int64) (*service.AccountVaultRecord, error) {
	if id <= 0 {
		return nil, service.ErrAccountVaultNotFound
	}
	return r.get(ctx, `SELECT `+accountVaultColumns+` FROM account_vault WHERE id = $1`, id)
}

func (r *accountVaultRepository) GetByEmail(ctx context.Context, email string) (*service.AccountVaultRecord, error) {
	email = normalizeAccountVaultEmail(email)
	if email == "" {
		return nil, service.ErrAccountVaultNotFound
	}
	return r.get(ctx, `SELECT `+accountVaultColumns+` FROM account_vault WHERE email = $1`, email)
}

func (r *accountVaultRepository) get(ctx context.Context, query string, arg any) (*service.AccountVaultRecord, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	record, err := scanAccountVaultRecord(r.db.QueryRowContext(ctx, query, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrAccountVaultNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get account vault record: %w", err)
	}
	return &record, nil
}

func (r *accountVaultRepository) GetByIDs(ctx context.Context, ids []int64) ([]service.AccountVaultRecord, error) {
	if len(ids) == 0 {
		return []service.AccountVaultRecord{}, nil
	}
	if len(ids) > accountVaultMaxBatchSize {
		return nil, errors.New("account vault batch exceeds 200 records")
	}
	for _, id := range ids {
		if id <= 0 {
			return nil, errors.New("account vault IDs must be positive")
		}
	}
	if err := r.ready(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+accountVaultColumns+` FROM account_vault WHERE id = ANY($1) ORDER BY id DESC`,
		pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("get account vault records: %w", err)
	}
	defer rows.Close()
	records, err := scanAccountVaultRows(rows)
	if err != nil {
		return nil, fmt.Errorf("get account vault records: %w", err)
	}
	return records, nil
}

func (r *accountVaultRepository) Create(ctx context.Context, record *service.AccountVaultRecord) (bool, error) {
	if err := r.ready(); err != nil {
		return false, err
	}
	if record == nil {
		return false, errors.New("account vault record is required")
	}
	email := normalizeAccountVaultEmail(record.Email)
	if email == "" || strings.TrimSpace(record.EncryptedData) == "" {
		return false, errors.New("account vault email and encrypted data are required")
	}

	// A single INSERT and the unique email constraint arbitrate concurrent
	// imports. DO NOTHING must never become an update of existing credentials.
	const query = `INSERT INTO account_vault
		(vault_id, email, issuer, has_password, algorithm, digits, period, encrypted_data, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (email) DO NOTHING
		RETURNING id, created_at, updated_at`
	var inserted service.AccountVaultRecord
	err := r.db.QueryRowContext(ctx, query,
		record.VaultID, email, record.Issuer, record.HasPassword, record.Algorithm,
		record.Digits, record.Period, record.EncryptedData, record.CreatedBy,
	).Scan(&inserted.ID, &inserted.CreatedAt, &inserted.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create account vault record: %w", err)
	}
	record.ID = inserted.ID
	record.Email = email
	record.CreatedAt = inserted.CreatedAt
	record.UpdatedAt = inserted.UpdatedAt
	record.RotationState = "required"
	return true, nil
}

func (r *accountVaultRepository) Delete(ctx context.Context, id int64) error {
	if id <= 0 {
		return service.ErrAccountVaultNotFound
	}
	if err := r.ready(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete account vault record: %w", err)
	}
	defer tx.Rollback()
	var lockedID int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM account_vault WHERE id=$1 FOR UPDATE`, id).Scan(&lockedID); errors.Is(err, sql.ErrNoRows) {
		return service.ErrAccountVaultNotFound
	} else if err != nil {
		return fmt.Errorf("delete account vault record: %w", err)
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_vault_rotation_jobs WHERE account_id=$1 AND status IN ('queued','running','paused'))`, id).Scan(&active); err != nil {
		return fmt.Errorf("delete account vault record: %w", err)
	}
	if active {
		return service.ErrVaultRotationActive
	}
	// Terminal job history can be removed; permanent first-completion ledger cannot.
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_vault_rotation_jobs WHERE account_id=$1 AND status IN ('completed','cancelled')`, id); err != nil {
		return fmt.Errorf("delete account vault record: %w", err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM account_vault WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete account vault record: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete account vault record: %w", err)
	}
	if affected != 1 {
		return service.ErrAccountVaultNotFound
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("delete account vault record: %w", err)
	}
	return nil
}

type accountVaultRowScanner interface {
	Scan(dest ...any) error
}

func scanAccountVaultRecord(row accountVaultRowScanner) (service.AccountVaultRecord, error) {
	var record service.AccountVaultRecord
	err := row.Scan(&record.ID, &record.VaultID, &record.Email, &record.Issuer,
		&record.HasPassword, &record.Algorithm, &record.Digits, &record.Period,
		&record.EncryptedData, &record.CreatedBy, &record.CreatedAt, &record.UpdatedAt, &record.RotationState, &record.RotationPhase, &record.RotationCompletedAt, &record.GroupName)
	return record, err
}

func scanAccountVaultRows(rows *sql.Rows) ([]service.AccountVaultRecord, error) {
	records := make([]service.AccountVaultRecord, 0)
	for rows.Next() {
		record, err := scanAccountVaultRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
