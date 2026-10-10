package repository

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"regexp"
	"strings"
	"testing"
	"time"
)

func rotationRepo(t *testing.T) (service.AccountVaultRotationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, m, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.ExpectationsWereMet()); db.Close() })
	return NewAccountVaultRotationRepository(db), m
}
func rotationRepoJob() service.AccountVaultRotationJob {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	expires := now.Add(90 * time.Second)
	return service.AccountVaultRotationJob{ID: "30000000-0000-4000-8000-000000000017", AccountID: 17, ActorID: 9, Provider: "chatgpt", Status: "running", Phase: "activate_intent", Revision: 8, Progress: "activate_intent", PendingEncrypted: "synthetic-encrypted-pending", SubjectHash: strings.Repeat("a", 64), BaseCipherHash: rotationCipherHash(accountVaultTestRecord().EncryptedData), LeaseHash: strings.Repeat("b", 64), LeaseExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}
}
func rotationRows(jobs ...service.AccountVaultRotationJob) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"id", "account_id", "actor_id", "provider", "status", "phase", "revision", "progress", "error_code", "pending_encrypted", "subject_hash", "base_cipher_hash", "lease_hash", "lease_expires_at", "created_at", "updated_at", "completed_at", "kind", "gateway_account_id"})
	for _, j := range jobs {
		rows.AddRow(j.ID, j.AccountID, j.ActorID, j.Provider, j.Status, j.Phase, j.Revision, j.Progress, j.ErrorCode, j.PendingEncrypted, j.SubjectHash, j.BaseCipherHash, j.LeaseHash, j.LeaseExpiresAt, j.CreatedAt, j.UpdatedAt, j.CompletedAt, j.Kind, j.GatewayAccountID)
	}
	return rows
}
func expectRotationLock(m sqlmock.Sqlmock, j service.AccountVaultRotationJob) {
	m.ExpectBegin()
	m.ExpectQuery(regexp.QuoteMeta(`SELECT account_id FROM account_vault_rotation_jobs WHERE id=$1 AND actor_id=$2`)).WithArgs(j.ID, j.ActorID).WillReturnRows(sqlmock.NewRows([]string{"account_id"}).AddRow(j.AccountID))
	m.ExpectQuery(regexp.QuoteMeta(`SELECT ` + accountVaultColumns + ` FROM account_vault WHERE id=$1 FOR UPDATE`)).WithArgs(j.AccountID).WillReturnRows(accountVaultTestRows(accountVaultTestRecord()))
	m.ExpectQuery(regexp.QuoteMeta(`SELECT `+rotationColumns+` FROM account_vault_rotation_jobs WHERE id=$1 AND actor_id=$2 FOR UPDATE`)).WithArgs(j.ID, j.ActorID).WillReturnRows(rotationRows(j))
}
func expectRotationAccountUpdate(m sqlmock.Sqlmock) {
	m.ExpectExec(`UPDATE account_vault SET rotation_state=`).WillReturnResult(sqlmock.NewResult(0, 1))
}
func expectRotationJobUpdate(m sqlmock.Sqlmock) {
	m.ExpectExec(`UPDATE account_vault_rotation_jobs SET status=`).WillReturnResult(sqlmock.NewResult(0, 1))
}
func expectRotationEvent(m sqlmock.Sqlmock, j service.AccountVaultRotationJob, phase, event string) {
	m.ExpectExec(`INSERT INTO account_vault_rotation_events`).WithArgs(j.ID, j.Revision, phase, event).WillReturnResult(sqlmock.NewResult(1, 1))
}
func rotationFence(j service.AccountVaultRotationJob) *service.AccountVaultRotationFence {
	return &service.AccountVaultRotationFence{Revision: j.Revision, LeaseHash: j.LeaseHash, Now: j.UpdatedAt}
}
func TestAccountVaultRotationRepositoryRejectsStaleLeaseBeforeCallback(t *testing.T) {
	for _, kind := range []string{"lease", "revision", "future_revision"} {
		t.Run(kind, func(t *testing.T) {
			repo, m := rotationRepo(t)
			j := rotationRepoJob()
			f := rotationFence(j)
			if kind == "lease" {
				f.LeaseHash = strings.Repeat("c", 64)
			} else if kind == "revision" {
				f.Revision--
			} else {
				f.AllowStaleRevision = true
				f.Revision++
			}
			expectRotationLock(m, j)
			m.ExpectRollback()
			called := false
			_, err := repo.Update(context.Background(), j.ActorID, j.ID, f, func(j service.AccountVaultRotationJob, r service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
				called = true
				return service.AccountVaultRotationMutation{}, nil
			})
			require.ErrorIs(t, err, service.ErrVaultRotationConflict)
			require.False(t, called)
		})
	}
}
func TestAccountVaultRotationRepositoryExpiredLeasePausesWithoutCallback(t *testing.T) {
	repo, m := rotationRepo(t)
	j := rotationRepoJob()
	j.Phase = "enroll_intent"
	f := rotationFence(j)
	f.Now = *j.LeaseExpiresAt
	expectRotationLock(m, j)
	expectRotationJobUpdate(m)
	expectRotationAccountUpdate(m)
	expected := j
	expected.Revision++
	expectRotationEvent(m, expected, "enroll_intent", "lease_expired")
	m.ExpectCommit()
	called := false
	_, err := repo.Update(context.Background(), j.ActorID, j.ID, f, func(j service.AccountVaultRotationJob, r service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
		called = true
		return service.AccountVaultRotationMutation{}, nil
	})
	require.ErrorIs(t, err, service.ErrVaultRotationConflict)
	require.False(t, called)
}
func TestAccountVaultRotationRepositoryHeartbeatAllowsOldRevision(t *testing.T) {
	repo, m := rotationRepo(t)
	j := rotationRepoJob()
	f := rotationFence(j)
	f.Revision--
	f.AllowStaleRevision = true
	expectRotationLock(m, j)
	expectRotationAccountUpdate(m)
	expectRotationJobUpdate(m)
	m.ExpectCommit()
	result, err := repo.Update(context.Background(), j.ActorID, j.ID, f, func(current service.AccountVaultRotationJob, _ service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
		require.Equal(t, j.Revision, current.Revision)
		return service.AccountVaultRotationMutation{Job: current}, nil
	})
	require.NoError(t, err)
	require.Equal(t, j.Revision, result.Revision)
}
func TestAccountVaultRotationRepositoryActorIsolation(t *testing.T) {
	repo, m := rotationRepo(t)
	j := rotationRepoJob()
	m.ExpectBegin()
	m.ExpectQuery(regexp.QuoteMeta(`SELECT account_id FROM account_vault_rotation_jobs WHERE id=$1 AND actor_id=$2`)).WithArgs(j.ID, int64(42)).WillReturnRows(sqlmock.NewRows([]string{"account_id"}))
	m.ExpectRollback()
	_, err := repo.Update(context.Background(), 42, j.ID, rotationFence(j), func(service.AccountVaultRotationJob, service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
		t.Fatal("cross-actor callback")
		return service.AccountVaultRotationMutation{}, nil
	})
	require.ErrorIs(t, err, service.ErrVaultRotationNotFound)
}
func TestAccountVaultRotationRepositoryCompletionIsAtomic(t *testing.T) {
	for _, stage := range []string{"success", "ledger_conflict", "credential_failure", "event_failure"} {
		t.Run(stage, func(t *testing.T) {
			repo, m := rotationRepo(t)
			j := rotationRepoJob()
			expectRotationLock(m, j)
			done := j
			done.Status = "completed"
			done.Phase = "completed"
			done.Progress = "completed"
			done.PendingEncrypted = ""
			done.LeaseHash = ""
			done.LeaseExpiresAt = nil
			done.Revision++
			at := j.UpdatedAt.Add(time.Second)
			done.CompletedAt = &at
			q := m.ExpectExec(`INSERT INTO account_vault_rotation_ledger`).WithArgs("chatgpt", "synthetic@example.test", j.SubjectHash, &at)
			if stage == "ledger_conflict" {
				q.WillReturnError(&pq.Error{Code: "23505"})
				m.ExpectRollback()
			} else {
				q.WillReturnResult(sqlmock.NewResult(0, 1))
				u := m.ExpectExec(regexp.QuoteMeta(`UPDATE account_vault SET encrypted_data=$2,algorithm='SHA1',digits=6,period=30,rotation_state='completed',rotation_phase='completed',rotation_completed_at=$3,updated_at=$3 WHERE id=$1 AND encrypted_data=$4`)).WithArgs(j.AccountID, "synthetic-new-encrypted-payload", &at, accountVaultTestRecord().EncryptedData)
				if stage == "credential_failure" {
					u.WillReturnError(errors.New("synthetic database failure"))
					m.ExpectRollback()
				} else {
					u.WillReturnResult(sqlmock.NewResult(0, 1))
					ev := m.ExpectExec(`INSERT INTO account_vault_rotation_events`).WithArgs(j.ID, done.Revision, "verified", "verified")
					if stage == "event_failure" {
						ev.WillReturnError(errors.New("synthetic event failure"))
						m.ExpectRollback()
					} else {
						ev.WillReturnResult(sqlmock.NewResult(1, 1))
						expectRotationJobUpdate(m)
						expectRotationEvent(m, done, "completed", "completed")
						m.ExpectCommit()
					}
				}
			}
			result, err := repo.Update(context.Background(), j.ActorID, j.ID, rotationFence(j), func(current service.AccountVaultRotationJob, r service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
				return service.AccountVaultRotationMutation{Job: done, Event: "completed", Complete: true, NewEncryptedData: "synthetic-new-encrypted-payload"}, nil
			})
			if stage == "success" {
				require.NoError(t, err)
				require.Equal(t, "completed", result.Status)
				require.Empty(t, result.PendingEncrypted)
			} else {
				require.Error(t, err)
				require.Nil(t, result)
				if stage == "ledger_conflict" {
					require.ErrorIs(t, err, service.ErrVaultRotationBlocked)
				}
			}
		})
	}
}
func TestAccountVaultRotationRepositoryPendingAndEventShareTransaction(t *testing.T) {
	repo, m := rotationRepo(t)
	j := rotationRepoJob()
	j.Phase = "enroll_intent"
	expectRotationLock(m, j)
	expectRotationAccountUpdate(m)
	expectRotationJobUpdate(m)
	m.ExpectExec(`INSERT INTO account_vault_rotation_events`).WillReturnError(errors.New("synthetic event failure"))
	m.ExpectRollback()
	result, err := repo.Update(context.Background(), j.ActorID, j.ID, rotationFence(j), func(j service.AccountVaultRotationJob, r service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
		j.PendingEncrypted = "synthetic-new-pending"
		j.Phase = "enrolled"
		j.Revision++
		return service.AccountVaultRotationMutation{Job: j, Event: "enrolled"}, nil
	})
	require.Error(t, err)
	require.Nil(t, result)
}
func TestAccountVaultRotationRepositoryLedgerSurvivesReimport(t *testing.T) {
	repo, m := rotationRepo(t)
	record := accountVaultTestRecord()
	m.ExpectBegin()
	m.ExpectQuery(regexp.QuoteMeta(`SELECT ` + accountVaultColumns + ` FROM account_vault WHERE id=$1 FOR UPDATE`)).WithArgs(record.ID).WillReturnRows(accountVaultTestRows(record))
	m.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM account_vault_rotation_ledger`).WithArgs("chatgpt", record.Email).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	m.ExpectExec(`UPDATE account_vault SET rotation_state='blocked'`).WithArgs(record.ID).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	job, status, err := repo.Queue(context.Background(), 9, record.ID, rotationRepoJob().ID, time.Now())
	require.ErrorIs(t, err, service.ErrVaultRotationBlocked)
	require.Equal(t, "blocked", status)
	require.Nil(t, job)
}
func TestAccountVaultRotationRepositoryExistingJobPreserved(t *testing.T) {
	repo, m := rotationRepo(t)
	j := rotationRepoJob()
	record := accountVaultTestRecord()
	m.ExpectBegin()
	m.ExpectQuery(regexp.QuoteMeta(`SELECT ` + accountVaultColumns + ` FROM account_vault WHERE id=$1 FOR UPDATE`)).WithArgs(record.ID).WillReturnRows(accountVaultTestRows(record))
	m.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM account_vault_rotation_ledger`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	m.ExpectQuery(regexp.QuoteMeta(`SELECT ` + rotationColumns + ` FROM account_vault_rotation_jobs WHERE account_id=$1 AND status IN ('queued','running','paused') FOR UPDATE`)).WithArgs(record.ID).WillReturnRows(rotationRows(j))
	m.ExpectCommit()
	job, status, err := repo.Queue(context.Background(), 9, record.ID, "40000000-0000-4000-8000-000000000017", time.Now())
	require.NoError(t, err)
	require.Equal(t, "existing", status)
	require.Equal(t, j.ID, job.ID)
	require.Equal(t, j.PendingEncrypted, job.PendingEncrypted)
}
func TestAccountVaultRotationRepositorySubjectLedgerBlocksBeforeDisable(t *testing.T) {
	for _, phase := range []string{"login", "prepared"} {
		t.Run(phase, func(t *testing.T) {
			repo, m := rotationRepo(t)
			j := rotationRepoJob()
			j.Phase = phase
			j.SubjectHash = strings.Repeat("d", 64)
			if phase == "login" {
				j.SubjectHash = ""
				j.PendingEncrypted = ""
			}
			expectRotationLock(m, j)
			m.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM account_vault_rotation_ledger`).WithArgs(j.Provider, "synthetic@example.test", strings.Repeat("d", 64)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
			m.ExpectRollback()
			_, err := repo.Update(context.Background(), j.ActorID, j.ID, rotationFence(j), func(j service.AccountVaultRotationJob, _ service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
				event := "prepared"
				j.Phase = "prepared"
				if phase == "prepared" {
					j.Phase = "disable_intent"
					event = "disable"
				}
				j.SubjectHash = strings.Repeat("d", 64)
				j.PendingEncrypted = "synthetic-encrypted-identities"
				j.Revision++
				return service.AccountVaultRotationMutation{Job: j, Event: event}, nil
			})
			require.ErrorIs(t, err, service.ErrVaultRotationBlocked)
		})
	}
}
func TestAccountVaultRotationRepositoryCapacityBlocksNextWorker(t *testing.T) {
	repo, m := rotationRepo(t)
	now := time.Now()
	m.ExpectBegin()
	m.ExpectQuery(`SELECT j.id FROM account_vault a JOIN account_vault_rotation_jobs`).WithArgs(int64(9), now).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	m.ExpectCommit()
	m.ExpectBegin()
	m.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_xact_lock(743, $1::integer)`)).WithArgs(int64(9)).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT COALESCE`).WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows([]string{"concurrency", "running"}).AddRow(2, 2))
	m.ExpectRollback()
	job, record, err := repo.Claim(context.Background(), 9, strings.Repeat("c", 64), now)
	require.NoError(t, err)
	require.Nil(t, job)
	require.Nil(t, record)
}
func TestAccountVaultRotationRepositoryClaimsBelowCapacity(t *testing.T) {
	repo, m := rotationRepo(t)
	now := time.Now()
	j := rotationRepoJob()
	j.Status, j.Phase = "queued", "login"
	m.ExpectBegin()
	m.ExpectQuery(`SELECT j.id FROM account_vault a JOIN account_vault_rotation_jobs`).WithArgs(int64(9), now).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	m.ExpectCommit()
	m.ExpectBegin()
	m.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_xact_lock(743, $1::integer)`)).WithArgs(int64(9)).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT COALESCE`).WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows([]string{"concurrency", "running"}).AddRow(2, 1))
	m.ExpectQuery(`SELECT j.id FROM account_vault a JOIN account_vault_rotation_jobs`).WithArgs(int64(9)).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(j.ID))
	m.ExpectQuery(regexp.QuoteMeta(`SELECT ` + rotationColumns + ` FROM account_vault_rotation_jobs WHERE id=$1`)).WithArgs(j.ID).WillReturnRows(rotationRows(j))
	m.ExpectQuery(regexp.QuoteMeta(`SELECT ` + accountVaultColumns + ` FROM account_vault WHERE id=$1`)).WithArgs(j.AccountID).WillReturnRows(accountVaultTestRows(accountVaultTestRecord()))
	expectRotationJobUpdate(m)
	expectRotationAccountUpdate(m)
	j.Revision++
	expectRotationEvent(m, j, "login", "claimed")
	m.ExpectCommit()
	job, record, err := repo.Claim(context.Background(), 9, strings.Repeat("c", 64), now)
	require.NoError(t, err)
	require.NotNil(t, record)
	require.Equal(t, "running", job.Status)
	require.Equal(t, now.Add(service.VaultRotationLease), *job.LeaseExpiresAt)
}
func TestAccountVaultRotationRepositoryConcurrencySettingUsesClaimLock(t *testing.T) {
	repo, m := rotationRepo(t)
	for _, invalid := range []int{0, -1, 5} {
		require.ErrorIs(t, repo.SetConcurrency(context.Background(), 9, invalid), service.ErrVaultRotationInvalid)
	}
	m.ExpectBegin()
	m.ExpectExec(regexp.QuoteMeta(`SELECT pg_advisory_xact_lock(743, $1::integer)`)).WithArgs(int64(9)).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(`INSERT INTO account_vault_rotation_settings`).WithArgs(int64(9), 4).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	require.NoError(t, repo.SetConcurrency(context.Background(), 9, 4))
}
func TestVaultSessionCompletionLeavesVaultAndMFALedgerUntouched(t *testing.T) {
	repo, m := rotationRepo(t)
	j := rotationRepoJob()
	j.Kind = "session"
	j.Phase = "prepared"
	j.SubjectHash = ""
	expectRotationLock(m, j)
	expectRotationJobUpdate(m)
	next := j
	next.Revision++
	expectRotationEvent(m, next, "completed", "session_imported")
	m.ExpectCommit()
	completed, err := repo.Update(context.Background(), j.ActorID, j.ID, rotationFence(j), func(job service.AccountVaultRotationJob, r service.AccountVaultRecord) (service.AccountVaultRotationMutation, error) {
		job.Revision++
		job.Phase = "completed"
		job.Status = "completed"
		job.GatewayAccountID = 42
		now := time.Now()
		job.CompletedAt = &now
		job.LeaseHash = ""
		job.LeaseExpiresAt = nil
		return service.AccountVaultRotationMutation{Job: job, Event: "session_imported"}, nil
	})
	require.NoError(t, err)
	require.Equal(t, int64(42), completed.GatewayAccountID)
}
