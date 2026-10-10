package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
	"time"
)

var _ service.AccountVaultAutomationRepository = (*accountVaultRotationRepository)(nil)

func (r *accountVaultRotationRepository) AutomationSettings(ctx context.Context) (*service.VaultAutomationSettings, error) {
	s := &service.VaultAutomationSettings{QueryIntervalSeconds: 60}
	err := r.db.QueryRowContext(ctx, `SELECT actor_id,token_version,enabled FROM account_vault_automation WHERE id=1`).Scan(&s.ActorID, &s.TokenVersion, &s.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil
	}
	return s, err
}
func (r *accountVaultRotationRepository) SaveAutomationSettings(ctx context.Context, s service.VaultAutomationSettings) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO account_vault_automation(id,actor_id,token_version,enabled) VALUES(1,$1,$2,$3) ON CONFLICT(id) DO UPDATE SET actor_id=$1,token_version=$2,enabled=$3,updated_at=NOW()`, s.ActorID, s.TokenVersion, s.Enabled)
	return err
}
func (r *accountVaultRotationRepository) LinkedAutomationAccounts(ctx context.Context) ([]service.VaultAutomationAccount, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT v.id,j.gateway_account_id,
 EXISTS(SELECT 1 FROM account_vault_rotation_jobs active WHERE active.account_id=v.id AND active.status IN ('queued','running')),
 EXISTS(SELECT 1 FROM account_vault_rotation_jobs paused WHERE paused.account_id=v.id AND paused.status='paused')
 FROM account_vault v JOIN LATERAL (SELECT gateway_account_id FROM account_vault_rotation_jobs WHERE account_id=v.id AND kind='session' AND status='completed' AND gateway_account_id>0 ORDER BY created_at DESC LIMIT 1) j ON true
 JOIN accounts a ON a.id=j.gateway_account_id AND a.deleted_at IS NULL WHERE a.platform='openai' AND a.type='oauth' ORDER BY v.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []service.VaultAutomationAccount{}
	for rows.Next() {
		var v service.VaultAutomationAccount
		if err = rows.Scan(&v.AccountID, &v.GatewayAccountID, &v.ActiveJob, &v.PausedJob); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
func (r *accountVaultRotationRepository) AutomationHealth(ctx context.Context, ids []int64) ([]service.VaultAccountHealth, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT account_id,gateway_account_id,status,error_code,checked_at,quota FROM account_vault_health WHERE account_id=ANY($1) ORDER BY account_id`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []service.VaultAccountHealth{}
	for rows.Next() {
		var h service.VaultAccountHealth
		var raw []byte
		if err = rows.Scan(&h.AccountID, &h.GatewayAccountID, &h.Status, &h.ErrorCode, &h.CheckedAt, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 && json.Unmarshal(raw, &h.Quota) != nil {
			return nil, errors.New("invalid quota metadata")
		}
		result = append(result, h)
	}
	return result, rows.Err()
}
func (r *accountVaultRotationRepository) SaveAutomationHealth(ctx context.Context, h service.VaultAccountHealth) error {
	raw, err := json.Marshal(h.Quota)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO account_vault_health(account_id,gateway_account_id,status,error_code,checked_at,quota) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(account_id) DO UPDATE SET gateway_account_id=$2,status=$3,error_code=$4,checked_at=$5,quota=$6`, h.AccountID, h.GatewayAccountID, h.Status, h.ErrorCode, h.CheckedAt, raw)
	return err
}
func (r *accountVaultRotationRepository) ClaimReauthorization(ctx context.Context, id int64, fingerprint string, now time.Time) (bool, error) {
	result, err := r.db.ExecContext(ctx, `UPDATE account_vault_health SET attempted_credential_hash=$2,last_attempt_at=$3 WHERE account_id=$1 AND attempted_credential_hash<>$2 AND (last_attempt_at IS NULL OR last_attempt_at<$3::timestamptz-INTERVAL '30 minutes')`, id, fingerprint, now)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}
