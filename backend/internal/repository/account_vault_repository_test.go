package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

const accountVaultTestSelect = `SELECT id, vault_id, email, issuer, has_password, algorithm,
digits, period, encrypted_data, created_by, created_at, updated_at, rotation_state, rotation_phase, rotation_completed_at, group_name FROM account_vault`

const accountVaultTestInsert = `INSERT INTO account_vault
(vault_id, email, issuer, has_password, algorithm, digits, period, encrypted_data, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (email) DO NOTHING RETURNING id, created_at, updated_at`

const accountVaultTestEnsureKey = `INSERT INTO account_vault_metadata (id, key_fingerprint)
VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id RETURNING key_fingerprint`

func newAccountVaultTestRepository(t *testing.T) (service.AccountVaultRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, mock.ExpectationsWereMet())
		_ = db.Close()
	})
	return NewAccountVaultRepository(db), mock
}

func accountVaultTestRecord() service.AccountVaultRecord {
	return service.AccountVaultRecord{
		ID: 17, VaultID: "00000000-0000-4000-8000-000000000017",
		Email: "synthetic@example.test", Issuer: "Synthetic issuer", HasPassword: true,
		Algorithm: "SHA256", Digits: 8, Period: 45,
		EncryptedData: "synthetic-opaque-ciphertext-only", CreatedBy: 9, RotationState: "required",
		CreatedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 10, 9, 12, 1, 0, 0, time.UTC),
	}
}

func accountVaultTestRows(records ...service.AccountVaultRecord) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"id", "vault_id", "email", "issuer", "has_password", "algorithm",
		"digits", "period", "encrypted_data", "created_by", "created_at", "updated_at", "rotation_state", "rotation_phase", "rotation_completed_at", "group_name"})
	for _, record := range records {
		rows.AddRow(record.ID, record.VaultID, record.Email, record.Issuer, record.HasPassword,
			record.Algorithm, record.Digits, record.Period, record.EncryptedData, record.CreatedBy,
			record.CreatedAt, record.UpdatedAt, record.RotationState, record.RotationPhase, record.RotationCompletedAt, record.GroupName)
	}
	return rows
}

func TestAccountVaultRepositoryEnsureKeyAtomicBinding(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	fingerprint := strings.Repeat("a1", 32)
	// Initial binding and later checks both use the same atomic statement.
	for range 2 {
		mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestEnsureKey)).WithArgs(fingerprint).
			WillReturnRows(sqlmock.NewRows([]string{"key_fingerprint"}).AddRow(fingerprint))
		require.NoError(t, repo.EnsureKey(context.Background(), fingerprint))
	}
}

func TestAccountVaultRepositoryEnsureKeyMismatchPreservesBinding(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	configured := strings.Repeat("a", 64)
	stored := strings.Repeat("b", 64)
	// The conflicting fingerprint is returned rather than overwritten. No
	// follow-up UPDATE, DELETE or credential write is expected or permitted.
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestEnsureKey)).WithArgs(configured).
		WillReturnRows(sqlmock.NewRows([]string{"key_fingerprint"}).AddRow(stored))
	err := repo.EnsureKey(context.Background(), configured)
	require.ErrorIs(t, err, service.ErrAccountVaultKeyMismatch)
	require.NotContains(t, err.Error(), configured)
	require.NotContains(t, err.Error(), stored)
}

func TestAccountVaultRepositoryEnsureKeyDatabaseError(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	databaseErr := errors.New("synthetic metadata database failure")
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestEnsureKey)).WillReturnError(databaseErr)
	err := repo.EnsureKey(context.Background(), strings.Repeat("0", 64))
	require.ErrorIs(t, err, databaseErr)
	require.NotErrorIs(t, err, service.ErrAccountVaultKeyMismatch)
}

func TestAccountVaultRepositoryEnsureKeyRejectsMalformedFingerprint(t *testing.T) {
	repo, _ := newAccountVaultTestRepository(t)
	for _, fingerprint := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		require.Error(t, repo.EnsureKey(context.Background(), fingerprint))
	}
}

func TestAccountVaultRepositoryCreate(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	record := accountVaultTestRecord()
	record.ID = 0
	record.Email = "  Synthetic@EXAMPLE.test  "
	record.CreatedAt = time.Time{}
	record.UpdatedAt = time.Time{}
	expected := accountVaultTestRecord()
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestInsert)).
		WithArgs(record.VaultID, expected.Email, record.Issuer, true, "SHA256", 8, 45, record.EncryptedData, int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(expected.ID, expected.CreatedAt, expected.UpdatedAt))

	created, err := repo.Create(context.Background(), &record)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, expected, record)
}

func TestAccountVaultRepositoryDuplicateDoesNotOverwrite(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	record := accountVaultTestRecord()
	record.ID = 0
	before := record
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestInsert)).
		WithArgs(record.VaultID, record.Email, record.Issuer, record.HasPassword, record.Algorithm,
			record.Digits, record.Period, record.EncryptedData, record.CreatedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}))

	created, err := repo.Create(context.Background(), &record)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, before, record)
}

func TestAccountVaultRepositoryCreateDatabaseError(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	record := accountVaultTestRecord()
	before := record
	databaseErr := errors.New("synthetic database failure")
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestInsert)).WillReturnError(databaseErr)
	created, err := repo.Create(context.Background(), &record)
	require.ErrorIs(t, err, databaseErr)
	require.False(t, created)
	require.Equal(t, before, record)
}

func TestAccountVaultRepositoryCreateRejectsMissingData(t *testing.T) {
	for _, field := range []string{"nil", "email", "encrypted_data"} {
		t.Run(field, func(t *testing.T) {
			repo, _ := newAccountVaultTestRepository(t)
			record := accountVaultTestRecord()
			input := &record
			switch field {
			case "nil":
				input = nil
			case "email":
				input.Email = "  "
			case "encrypted_data":
				input.EncryptedData = "  "
			}
			created, err := repo.Create(context.Background(), input)
			require.Error(t, err)
			require.False(t, created)
		})
	}
}

func TestAccountVaultRepositoryGet(t *testing.T) {
	for _, byEmail := range []bool{false, true} {
		name := "by_id"
		if byEmail {
			name = "by_normalized_email"
		}
		t.Run(name, func(t *testing.T) {
			repo, mock := newAccountVaultTestRepository(t)
			expected := accountVaultTestRecord()
			query := accountVaultTestSelect + ` WHERE id = $1`
			var argument any = expected.ID
			if byEmail {
				query = accountVaultTestSelect + ` WHERE email = $1`
				argument = expected.Email
			}
			mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs(argument).WillReturnRows(accountVaultTestRows(expected))
			var record *service.AccountVaultRecord
			var err error
			if byEmail {
				record, err = repo.GetByEmail(context.Background(), "  Synthetic@EXAMPLE.test ")
			} else {
				record, err = repo.GetByID(context.Background(), expected.ID)
			}
			require.NoError(t, err)
			require.Equal(t, &expected, record)
		})
	}
}

func TestAccountVaultRepositoryGetNotFound(t *testing.T) {
	t.Run("id", func(t *testing.T) {
		repo, mock := newAccountVaultTestRepository(t)
		mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect + ` WHERE id = $1`)).
			WithArgs(int64(17)).WillReturnError(sql.ErrNoRows)
		record, err := repo.GetByID(context.Background(), 17)
		require.Nil(t, record)
		require.ErrorIs(t, err, service.ErrAccountVaultNotFound)
	})
	t.Run("email", func(t *testing.T) {
		repo, mock := newAccountVaultTestRepository(t)
		mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect + ` WHERE email = $1`)).
			WithArgs("absent@example.test").WillReturnRows(accountVaultTestRows())
		record, err := repo.GetByEmail(context.Background(), "Absent@EXAMPLE.test")
		require.Nil(t, record)
		require.ErrorIs(t, err, service.ErrAccountVaultNotFound)
	})
}

func TestAccountVaultRepositoryGetDatabaseError(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	databaseErr := errors.New("synthetic read failure")
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect + ` WHERE id = $1`)).WillReturnError(databaseErr)
	record, err := repo.GetByID(context.Background(), 17)
	require.Nil(t, record)
	require.ErrorIs(t, err, databaseErr)
}

func TestAccountVaultRepositoryList(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	first := accountVaultTestRecord()
	second := first
	second.ID = 16
	second.Email = "second@example.test"
	second.VaultID = "00000000-0000-4000-8000-000000000016"
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM account_vault`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(27)))
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect+` ORDER BY id DESC LIMIT $1 OFFSET $2`)).
		WithArgs(25, int64(25)).WillReturnRows(accountVaultTestRows(first, second)).RowsWillBeClosed()
	records, total, err := repo.List(context.Background(), 2, 25, "")
	require.NoError(t, err)
	require.EqualValues(t, 27, total)
	require.Equal(t, []service.AccountVaultRecord{first, second}, records)
}

func TestAccountVaultRepositorySearchIsParameterizedAndLiteral(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	const where = ` WHERE (email ILIKE $1 ESCAPE '\' OR issuer ILIKE $1 ESCAPE '\')`
	const search = `  50%_\' OR 1=1 --  `
	const pattern = `%50\%\_\\' OR 1=1 --%`
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM account_vault` + where)).
		WithArgs(pattern).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect+where+` ORDER BY id DESC LIMIT $2 OFFSET $3`)).
		WithArgs(pattern, 20, int64(0)).WillReturnRows(accountVaultTestRows()).RowsWillBeClosed()
	records, total, err := repo.List(context.Background(), 0, 0, search)
	require.NoError(t, err)
	require.Zero(t, total)
	require.NotNil(t, records)
	require.Empty(t, records)
}

func TestAccountVaultRepositoryListCapsPageSize(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM account_vault`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect+` ORDER BY id DESC LIMIT $1 OFFSET $2`)).
		WithArgs(200, int64(0)).WillReturnRows(accountVaultTestRows())
	_, _, err := repo.List(context.Background(), 1, 1000000, "")
	require.NoError(t, err)
}

func TestAccountVaultRepositoryListErrors(t *testing.T) {
	for _, stage := range []string{"count", "query", "row", "scan"} {
		t.Run(stage, func(t *testing.T) {
			repo, mock := newAccountVaultTestRepository(t)
			databaseErr := errors.New("synthetic list failure")
			countQuery := mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM account_vault`))
			if stage == "count" {
				countQuery.WillReturnError(databaseErr)
			} else {
				countQuery.WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				query := mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect + ` ORDER BY id DESC LIMIT $1 OFFSET $2`))
				switch stage {
				case "query":
					query.WillReturnError(databaseErr)
				case "row":
					query.WillReturnRows(accountVaultTestRows(accountVaultTestRecord()).RowError(0, databaseErr)).RowsWillBeClosed()
				case "scan":
					query.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("invalid row")).RowsWillBeClosed()
				}
			}
			records, _, err := repo.List(context.Background(), 1, 20, "")
			require.Error(t, err)
			require.Nil(t, records)
			if stage != "scan" {
				require.ErrorIs(t, err, databaseErr)
			}
		})
	}
}

func TestAccountVaultRepositoryGetByIDs(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	record := accountVaultTestRecord()
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect + ` WHERE id = ANY($1) ORDER BY id DESC`)).
		WithArgs("{17,18,17}").WillReturnRows(accountVaultTestRows(record)).RowsWillBeClosed()
	records, err := repo.GetByIDs(context.Background(), []int64{17, 18, 17})
	require.NoError(t, err)
	require.Equal(t, []service.AccountVaultRecord{record}, records)
}

func TestAccountVaultRepositoryGetByIDsValidatesBatch(t *testing.T) {
	repo, _ := newAccountVaultTestRepository(t)
	records, err := repo.GetByIDs(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, records)
	require.Empty(t, records)
	_, err = repo.GetByIDs(context.Background(), make([]int64, 201))
	require.Error(t, err)
	_, err = repo.GetByIDs(context.Background(), []int64{17, -1})
	require.Error(t, err)
}

func TestAccountVaultRepositoryGetByIDsErrors(t *testing.T) {
	for _, stage := range []string{"query", "row"} {
		t.Run(stage, func(t *testing.T) {
			repo, mock := newAccountVaultTestRepository(t)
			databaseErr := errors.New("synthetic batch read failure")
			query := mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect + ` WHERE id = ANY($1) ORDER BY id DESC`))
			if stage == "query" {
				query.WillReturnError(databaseErr)
			} else {
				query.WillReturnRows(accountVaultTestRows(accountVaultTestRecord()).RowError(0, databaseErr)).RowsWillBeClosed()
			}
			records, err := repo.GetByIDs(context.Background(), []int64{17})
			require.ErrorIs(t, err, databaseErr)
			require.Nil(t, records)
		})
	}
}

func expectVaultDeleteLock(mock sqlmock.Sqlmock, id int64, active bool) {
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM account_vault WHERE id=$1 FOR UPDATE`)).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM account_vault_rotation_jobs WHERE account_id=$1 AND status IN ('queued','running','paused'))`)).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(active))
}
func TestAccountVaultRepositoryDelete(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	expectVaultDeleteLock(mock, 17, false)
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM account_vault_rotation_jobs WHERE account_id=$1 AND status IN ('completed','cancelled')`)).WithArgs(int64(17)).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM account_vault WHERE id = $1`)).WithArgs(int64(17)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	require.NoError(t, repo.Delete(context.Background(), 17))
}
func TestAccountVaultRepositoryDeleteNotFound(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM account_vault WHERE id=$1 FOR UPDATE`)).WithArgs(int64(17)).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectRollback()
	require.ErrorIs(t, repo.Delete(context.Background(), 17), service.ErrAccountVaultNotFound)
}
func TestAccountVaultRepositoryDeleteActiveRotationIsAtomic(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	expectVaultDeleteLock(mock, 17, true)
	mock.ExpectRollback()
	require.ErrorIs(t, repo.Delete(context.Background(), 17), service.ErrVaultRotationActive)
}
func TestAccountVaultRepositoryDeleteErrors(t *testing.T) {
	for _, stage := range []string{"exec", "result"} {
		t.Run(stage, func(t *testing.T) {
			repo, mock := newAccountVaultTestRepository(t)
			expectVaultDeleteLock(mock, 17, false)
			mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM account_vault_rotation_jobs WHERE account_id=$1 AND status IN ('completed','cancelled')`)).WillReturnResult(sqlmock.NewResult(0, 0))
			databaseErr := errors.New("synthetic delete failure")
			query := mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM account_vault WHERE id = $1`))
			if stage == "exec" {
				query.WillReturnError(databaseErr)
			} else {
				query.WillReturnResult(sqlmock.NewErrorResult(databaseErr))
			}
			mock.ExpectRollback()
			require.ErrorIs(t, repo.Delete(context.Background(), 17), databaseErr)
		})
	}
}

func TestAccountVaultRepositoryInvalidLookupDoesNotQuery(t *testing.T) {
	repo, _ := newAccountVaultTestRepository(t)
	_, err := repo.GetByID(context.Background(), 0)
	require.ErrorIs(t, err, service.ErrAccountVaultNotFound)
	_, err = repo.GetByEmail(context.Background(), "   ")
	require.ErrorIs(t, err, service.ErrAccountVaultNotFound)
	require.ErrorIs(t, repo.Delete(context.Background(), -1), service.ErrAccountVaultNotFound)
}

func TestAccountVaultRepositoryMissingDatabase(t *testing.T) {
	repo := NewAccountVaultRepository(nil)
	require.Error(t, repo.EnsureKey(context.Background(), strings.Repeat("a", 64)))
	_, _, err := repo.List(context.Background(), 1, 20, "")
	require.Error(t, err)
	_, err = repo.GetByID(context.Background(), 17)
	require.Error(t, err)
	_, err = repo.GetByEmail(context.Background(), "synthetic@example.test")
	require.Error(t, err)
	_, err = repo.GetByIDs(context.Background(), []int64{17})
	require.Error(t, err)
	record := accountVaultTestRecord()
	_, err = repo.Create(context.Background(), &record)
	require.Error(t, err)
	require.Error(t, repo.Delete(context.Background(), 17))
}
