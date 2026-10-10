package repository

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestVaultAutomationClaimIsDurableConditionalAndPreservedByStatusUpdates(t *testing.T) {
	base, m := rotationRepo(t)
	r := base.(service.AccountVaultAutomationRepository)
	now := time.Now()
	// The database owns both deduplication and the 30 minute cooldown, including after restart.
	query := `UPDATE account_vault_health SET attempted_credential_hash=\$2,last_attempt_at=\$3 WHERE account_id=\$1 AND attempted_credential_hash<>\$2 AND \(last_attempt_at IS NULL OR last_attempt_at<\$3::timestamptz-INTERVAL '30 minutes'\)`
	m.ExpectExec(query).WithArgs(int64(7), "synthetic-hash", now).WillReturnResult(sqlmock.NewResult(0, 1))
	claimed, err := r.ClaimReauthorization(context.Background(), 7, "synthetic-hash", now)
	require.NoError(t, err)
	require.True(t, claimed)
	m.ExpectExec(query).WithArgs(int64(7), "synthetic-hash", now).WillReturnResult(sqlmock.NewResult(0, 0))
	claimed, err = r.ClaimReauthorization(context.Background(), 7, "synthetic-hash", now)
	require.NoError(t, err)
	require.False(t, claimed)
	m.ExpectExec(`INSERT INTO account_vault_health.*ON CONFLICT\(account_id\) DO UPDATE SET gateway_account_id=\$2,status=\$3,error_code=\$4,checked_at=\$5,quota=\$6$`).WithArgs(int64(7), int64(100), "error", "token_revoked", now, []byte("null")).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, r.SaveAutomationHealth(context.Background(), service.VaultAccountHealth{AccountID: 7, GatewayAccountID: 100, Status: "error", ErrorCode: "token_revoked", CheckedAt: now}))
}
