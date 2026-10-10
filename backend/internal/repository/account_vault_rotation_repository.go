package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

type accountVaultRotationRepository struct{ db *sql.DB }

var _ service.AccountVaultRotationRepository = (*accountVaultRotationRepository)(nil)

func NewAccountVaultRotationRepository(db *sql.DB) service.AccountVaultRotationRepository {
	return &accountVaultRotationRepository{db: db}
}

const rotationColumns = `id, account_id, actor_id, provider, status, phase, revision, progress, error_code,
pending_encrypted, subject_hash, base_cipher_hash, lease_hash, lease_expires_at, created_at, updated_at, completed_at, kind, gateway_account_id`

func scanRotationJob(row accountVaultRowScanner) (service.AccountVaultRotationJob, error) {
	var j service.AccountVaultRotationJob
	err := row.Scan(&j.ID, &j.AccountID, &j.ActorID, &j.Provider, &j.Status, &j.Phase, &j.Revision, &j.Progress, &j.ErrorCode, &j.PendingEncrypted, &j.SubjectHash, &j.BaseCipherHash, &j.LeaseHash, &j.LeaseExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.CompletedAt, &j.Kind, &j.GatewayAccountID)
	return j, err
}
func rotationCipherHash(v string) string {
	s := sha256.Sum256([]byte(v))
	return hex.EncodeToString(s[:])
}
func (r *accountVaultRotationRepository) begin(ctx context.Context) (*sql.Tx, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("rotation storage unavailable")
	}
	return r.db.BeginTx(ctx, nil)
}
func rotationEvent(ctx context.Context, tx *sql.Tx, j service.AccountVaultRotationJob, event string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO account_vault_rotation_events (job_id, revision, phase, event) VALUES ($1,$2,$3,$4)`, j.ID, j.Revision, j.Phase, event)
	return err
}
func updateRotationRow(ctx context.Context, tx *sql.Tx, j service.AccountVaultRotationJob) error {
	_, err := tx.ExecContext(ctx, `UPDATE account_vault_rotation_jobs SET status=$2, phase=$3, revision=$4, progress=$5, error_code=$6, pending_encrypted=$7, subject_hash=$8, lease_hash=$9, lease_expires_at=$10, updated_at=$11, completed_at=$12,gateway_account_id=$13 WHERE id=$1`, j.ID, j.Status, j.Phase, j.Revision, j.Progress, j.ErrorCode, j.PendingEncrypted, j.SubjectHash, j.LeaseHash, j.LeaseExpiresAt, j.UpdatedAt, j.CompletedAt, j.GatewayAccountID)
	return err
}
func updateRotationAccount(ctx context.Context, tx *sql.Tx, j service.AccountVaultRotationJob) error {
	if j.Kind == "session" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE account_vault SET rotation_state=$2, rotation_phase=$3, rotation_completed_at=$4 WHERE id=$1`, j.AccountID, j.Status, j.Phase, j.CompletedAt)
	return err
}
func isRotationUnique(err error) bool {
	var pe *pq.Error
	return errors.As(err, &pe) && pe.Code == "23505"
}
func (r *accountVaultRotationRepository) Queue(ctx context.Context, actorID, accountID int64, id string, now time.Time) (*service.AccountVaultRotationJob, string, error) {
	return r.queueKind(ctx, actorID, accountID, id, now, "rotation")
}
func (r *accountVaultRotationRepository) QueueSession(ctx context.Context, actorID, accountID int64, id string, now time.Time) (*service.AccountVaultRotationJob, string, error) {
	return r.queueKind(ctx, actorID, accountID, id, now, "session")
}
func (r *accountVaultRotationRepository) queueKind(ctx context.Context, actorID, accountID int64, id string, now time.Time, kind string) (*service.AccountVaultRotationJob, string, error) {
	tx, err := r.begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	record, err := scanAccountVaultRecord(tx.QueryRowContext(ctx, `SELECT `+accountVaultColumns+` FROM account_vault WHERE id=$1 FOR UPDATE`, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", service.ErrAccountVaultNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if kind == "rotation" {
		var completed bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_vault_rotation_ledger WHERE provider=$1 AND email=$2)`, service.VaultRotationProvider, record.Email).Scan(&completed); err != nil {
			return nil, "", err
		}
		if completed || record.RotationState == "completed" {
			if record.RotationState != "completed" {
				if _, err = tx.ExecContext(ctx, `UPDATE account_vault SET rotation_state='blocked' WHERE id=$1`, accountID); err != nil {
					return nil, "", err
				}
			}
			if err = tx.Commit(); err != nil {
				return nil, "", err
			}
			return nil, "blocked", service.ErrVaultRotationBlocked
		}
	}
	existing, err := scanRotationJob(tx.QueryRowContext(ctx, `SELECT `+rotationColumns+` FROM account_vault_rotation_jobs WHERE account_id=$1 AND status IN ('queued','running','paused') FOR UPDATE`, accountID))
	if err == nil {
		if existing.ActorID != actorID || (existing.Kind != "" && existing.Kind != kind) {
			return nil, "", service.ErrVaultRotationActive
		}
		if err = tx.Commit(); err != nil {
			return nil, "", err
		}
		return &existing, "existing", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	j := service.AccountVaultRotationJob{Kind: kind, ID: id, AccountID: accountID, ActorID: actorID, Provider: service.VaultRotationProvider, Status: "queued", Phase: "login", Revision: 1, Progress: "queued", BaseCipherHash: rotationCipherHash(record.EncryptedData), CreatedAt: now, UpdatedAt: now}
	_, err = tx.ExecContext(ctx, `INSERT INTO account_vault_rotation_jobs (id,account_id,actor_id,provider,status,phase,revision,progress,base_cipher_hash,created_at,updated_at,kind) VALUES ($1,$2,$3,$4,'queued','login',1,'queued',$5,$6,$6,$7)`, j.ID, j.AccountID, j.ActorID, j.Provider, j.BaseCipherHash, now, kind)
	if err != nil {
		return nil, "", err
	}
	if err = updateRotationAccount(ctx, tx, j); err != nil {
		return nil, "", err
	}
	if err = rotationEvent(ctx, tx, j, "queued"); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return &j, "queued", nil
}

// Expiration only pauses work. It never creates a retry or rewinds a phase.
// SKIP LOCKED avoids interfering with an in-flight committed checkpoint.
func (r *accountVaultRotationRepository) expire(ctx context.Context, actorID int64, now time.Time) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT j.id FROM account_vault a JOIN account_vault_rotation_jobs j ON j.account_id=a.id WHERE j.actor_id=$1 AND j.status='running' AND j.lease_expires_at <= $2 ORDER BY a.id FOR UPDATE OF a,j SKIP LOCKED`, actorID, now)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		j, err := scanRotationJob(tx.QueryRowContext(ctx, `SELECT `+rotationColumns+` FROM account_vault_rotation_jobs WHERE id=$1`, id))
		if err != nil {
			return err
		}
		j.Status = "paused"
		j.Progress = "paused"
		j.ErrorCode = "lease_expired"
		if j.Phase == "enroll_intent" {
			j.ErrorCode = "enrollment_uncertain"
		}
		j.LeaseHash = ""
		j.LeaseExpiresAt = nil
		j.Revision++
		j.UpdatedAt = now
		if err = updateRotationRow(ctx, tx, j); err != nil {
			return err
		}
		if err = updateRotationAccount(ctx, tx, j); err != nil {
			return err
		}
		if err = rotationEvent(ctx, tx, j, "lease_expired"); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (r *accountVaultRotationRepository) Query(ctx context.Context, actorID int64, ids []int64) ([]service.AccountVaultRotationJob, error) {
	return r.queryKind(ctx, actorID, ids, "rotation")
}
func (r *accountVaultRotationRepository) QuerySessions(ctx context.Context, actorID int64, ids []int64) ([]service.AccountVaultRotationJob, error) {
	return r.queryKind(ctx, actorID, ids, "session")
}
func (r *accountVaultRotationRepository) queryKind(ctx context.Context, actorID int64, ids []int64, kind string) ([]service.AccountVaultRotationJob, error) {
	if len(ids) > 200 {
		return nil, service.ErrVaultRotationInvalid
	}
	if err := r.expire(ctx, actorID, time.Now()); err != nil {
		return nil, err
	}
	query := `SELECT ` + rotationColumns + ` FROM (SELECT DISTINCT ON (account_id) ` + rotationColumns + ` FROM account_vault_rotation_jobs WHERE actor_id=$1 AND kind='` + kind + `'`
	args := []any{actorID}
	if len(ids) > 0 {
		query += ` AND account_id=ANY($2)`
		args = append(args, pq.Array(ids))
	}
	query += ` ORDER BY account_id,created_at DESC,id DESC) latest ORDER BY created_at DESC`
	if len(ids) == 0 {
		query += ` LIMIT 100`
	} else {
		query += ` LIMIT 200`
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []service.AccountVaultRotationJob{}
	seen := map[int64]bool{}
	for rows.Next() {
		j, err := scanRotationJob(rows)
		if err != nil {
			return nil, err
		}
		if !seen[j.AccountID] {
			jobs = append(jobs, j)
			seen[j.AccountID] = true
		}
		if len(ids) == 0 && len(jobs) >= 100 {
			break
		}
	}
	return jobs, rows.Err()
}
func (r *accountVaultRotationRepository) Claim(ctx context.Context, actorID int64, leaseHash string, now time.Time) (*service.AccountVaultRotationJob, *service.AccountVaultRecord, error) {
	if err := r.expire(ctx, actorID, now); err != nil {
		return nil, nil, err
	}
	tx, err := r.begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	// Serialize capacity checks across worker processes for this administrator.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(743, $1::integer)`, actorID%2147483647); err != nil {
		return nil, nil, err
	}
	var concurrency, running int
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT concurrency FROM account_vault_rotation_settings WHERE actor_id=$1),2), (SELECT count(*) FROM account_vault_rotation_jobs WHERE actor_id=$1 AND status='running')`, actorID).Scan(&concurrency, &running); err != nil {
		return nil, nil, err
	}
	if running >= concurrency {
		return nil, nil, nil
	}

	var id string
	err = tx.QueryRowContext(ctx, `SELECT j.id FROM account_vault a JOIN account_vault_rotation_jobs j ON j.account_id=a.id WHERE j.actor_id=$1 AND j.status='queued' ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF a,j SKIP LOCKED`, actorID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	j, err := scanRotationJob(tx.QueryRowContext(ctx, `SELECT `+rotationColumns+` FROM account_vault_rotation_jobs WHERE id=$1`, id))
	if err != nil {
		return nil, nil, err
	}
	record, err := scanAccountVaultRecord(tx.QueryRowContext(ctx, `SELECT `+accountVaultColumns+` FROM account_vault WHERE id=$1`, j.AccountID))
	if err != nil {
		return nil, nil, err
	}
	expires := now.Add(service.VaultRotationLease)
	j.Status = "running"
	j.Progress = j.Phase
	j.Revision++
	j.LeaseHash = leaseHash
	j.LeaseExpiresAt = &expires
	j.UpdatedAt = now
	if err = updateRotationRow(ctx, tx, j); err != nil {
		return nil, nil, err
	}
	if err = updateRotationAccount(ctx, tx, j); err != nil {
		return nil, nil, err
	}
	if err = rotationEvent(ctx, tx, j, "claimed"); err != nil {
		return nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, err
	}
	return &j, &record, nil
}
func (r *accountVaultRotationRepository) SetConcurrency(ctx context.Context, actorID int64, concurrency int) error {
	if concurrency < 1 || concurrency > service.VaultRotationMaxConcurrency {
		return service.ErrVaultRotationInvalid
	}
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(743, $1::integer)`, actorID%2147483647); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_vault_rotation_settings(actor_id,concurrency) VALUES($1,$2) ON CONFLICT(actor_id) DO UPDATE SET concurrency=EXCLUDED.concurrency,updated_at=NOW()`, actorID, concurrency); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *accountVaultRotationRepository) Update(ctx context.Context, actorID int64, id string, fence *service.AccountVaultRotationFence, fn service.AccountVaultRotationUpdate) (*service.AccountVaultRotationJob, error) {
	tx, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var accountID int64
	err = tx.QueryRowContext(ctx, `SELECT account_id FROM account_vault_rotation_jobs WHERE id=$1 AND actor_id=$2`, id, actorID).Scan(&accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrVaultRotationNotFound
	}
	if err != nil {
		return nil, err
	}
	record, err := scanAccountVaultRecord(tx.QueryRowContext(ctx, `SELECT `+accountVaultColumns+` FROM account_vault WHERE id=$1 FOR UPDATE`, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrVaultRotationNotFound
	}
	if err != nil {
		return nil, err
	}
	j, err := scanRotationJob(tx.QueryRowContext(ctx, `SELECT `+rotationColumns+` FROM account_vault_rotation_jobs WHERE id=$1 AND actor_id=$2 FOR UPDATE`, id, actorID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrVaultRotationNotFound
	}
	if err != nil {
		return nil, err
	}
	if fence != nil {
		if j.Status != "running" || j.LeaseHash == "" || j.LeaseHash != fence.LeaseHash || j.LeaseExpiresAt == nil {
			return nil, service.ErrVaultRotationConflict
		}
		if !j.LeaseExpiresAt.After(fence.Now) {
			j.Status = "paused"
			j.Progress = "paused"
			j.ErrorCode = "lease_expired"
			if j.Phase == "enroll_intent" {
				j.ErrorCode = "enrollment_uncertain"
			}
			j.LeaseHash = ""
			j.LeaseExpiresAt = nil
			j.Revision++
			j.UpdatedAt = fence.Now
			if err = updateRotationRow(ctx, tx, j); err != nil {
				return nil, err
			}
			if err = updateRotationAccount(ctx, tx, j); err != nil {
				return nil, err
			}
			if err = rotationEvent(ctx, tx, j, "lease_expired"); err != nil {
				return nil, err
			}
			if err = tx.Commit(); err != nil {
				return nil, err
			}
			return nil, service.ErrVaultRotationConflict
		}
		if (!fence.AllowStaleRevision && j.Revision != fence.Revision) || (fence.AllowStaleRevision && fence.Revision > j.Revision) {
			return nil, service.ErrVaultRotationConflict
		}
	}
	mutation, err := fn(j, record)
	if err != nil {
		return nil, err
	}
	next := mutation.Job
	if next.ID != j.ID || next.Kind != j.Kind || next.AccountID != j.AccountID || next.ActorID != j.ActorID || next.Provider != j.Provider || next.BaseCipherHash != j.BaseCipherHash || next.Revision < j.Revision || next.Revision > j.Revision+1 {
		return nil, service.ErrVaultRotationConflict
	}
	// Recheck immediately before granting disable: another job can finish while
	// this job waits for the active-subject unique index during preparation.
	if next.SubjectHash != "" && (next.SubjectHash != j.SubjectHash || next.Phase == "disable_intent") {
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_vault_rotation_ledger WHERE provider=$1 AND (email=$2 OR subject_hash=$3))`, j.Provider, record.Email, next.SubjectHash).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return nil, service.ErrVaultRotationBlocked
		}
	}
	if mutation.Complete {
		if j.Kind == "session" {
			return nil, service.ErrVaultRotationInvalid
		}
		if next.Status != "completed" || next.Phase != "completed" || next.PendingEncrypted != "" || mutation.NewEncryptedData == "" || next.SubjectHash == "" || next.CompletedAt == nil || rotationCipherHash(record.EncryptedData) != j.BaseCipherHash {
			return nil, service.ErrVaultRotationConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO account_vault_rotation_ledger(provider,email,subject_hash,completed_at) VALUES($1,$2,$3,$4)`, j.Provider, record.Email, next.SubjectHash, next.CompletedAt)
		if isRotationUnique(err) {
			return nil, service.ErrVaultRotationBlocked
		}
		if err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE account_vault SET encrypted_data=$2,algorithm='SHA1',digits=6,period=30,rotation_state='completed',rotation_phase='completed',rotation_completed_at=$3,updated_at=$3 WHERE id=$1 AND encrypted_data=$4`, accountID, mutation.NewEncryptedData, next.CompletedAt, record.EncryptedData)
		if err != nil {
			return nil, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if affected != 1 {
			return nil, service.ErrVaultRotationConflict
		}
		verified := next
		verified.Phase = "verified"
		if err = rotationEvent(ctx, tx, verified, "verified"); err != nil {
			return nil, err
		}
	} else {
		if mutation.NewEncryptedData != "" {
			return nil, service.ErrVaultRotationConflict
		}
		if err = updateRotationAccount(ctx, tx, next); err != nil {
			return nil, err
		}
	}
	if err = updateRotationRow(ctx, tx, next); isRotationUnique(err) {
		return nil, service.ErrVaultRotationActive
	} else if err != nil {
		return nil, err
	}
	if mutation.Event != "" {
		if err = rotationEvent(ctx, tx, next, mutation.Event); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &next, nil
}
func (r *accountVaultRotationRepository) CreateToken(ctx context.Context, token service.AccountVaultWorkerToken) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize token replacement/revocation across concurrent instances per actor.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(742, $1::integer)`, token.ActorID%2147483647); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE account_vault_worker_tokens SET revoked=TRUE WHERE actor_id=$1 AND revoked=FALSE`, token.ActorID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_vault_worker_tokens(id,actor_id,token_version,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, token.ID, token.ActorID, token.TokenVersion, token.Hash, token.ExpiresAt); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *accountVaultRotationRepository) FindToken(ctx context.Context, hash string) (*service.AccountVaultWorkerToken, error) {
	if len(hash) != 64 || strings.TrimSpace(hash) != hash {
		return nil, service.ErrVaultWorkerUnauthorized
	}
	if r == nil || r.db == nil {
		return nil, service.ErrVaultWorkerUnauthorized
	}
	var t service.AccountVaultWorkerToken
	err := r.db.QueryRowContext(ctx, `SELECT id,actor_id,token_version,token_hash,expires_at,revoked FROM account_vault_worker_tokens WHERE token_hash=$1`, hash).Scan(&t.ID, &t.ActorID, &t.TokenVersion, &t.Hash, &t.ExpiresAt, &t.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrVaultWorkerUnauthorized
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}
func (r *accountVaultRotationRepository) RevokeTokens(ctx context.Context, actorID int64) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(742, $1::integer)`, actorID%2147483647); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE account_vault_worker_tokens SET revoked=TRUE WHERE actor_id=$1 AND revoked=FALSE`, actorID); err != nil {
		return err
	}
	return tx.Commit()
}
