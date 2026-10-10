package repository

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"regexp"
	"testing"
)

func TestAccountVaultGroupFilterUsesExactGroupAndPagedSearch(t *testing.T) {
	repo, mock := newAccountVaultTestRepository(t)
	groupRepo := repo.(service.AccountVaultGroupingRepository)
	where := ` WHERE (email ILIKE $1 ESCAPE '\' OR issuer ILIKE $1 ESCAPE '\') AND group_name = $2`
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM account_vault"+where)).WithArgs("%account%", "组_%").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	record := accountVaultTestRecord()
	record.GroupName = "组_%"
	mock.ExpectQuery(regexp.QuoteMeta(accountVaultTestSelect+where+" ORDER BY id DESC LIMIT $3 OFFSET $4")).WithArgs("%account%", "组_%", 2, 2).WillReturnRows(accountVaultTestRows(record))
	rows, count, err := groupRepo.ListByGroup(context.Background(), 2, 2, "account", "组_%")
	require.NoError(t, err)
	require.Equal(t, int64(3), count)
	require.Equal(t, "组_%", rows[0].GroupName)
}

func TestAccountVaultGroupAssignmentIsAtomicWhenAnAccountDisappears(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete batch", true: "missing account"}[missing], func(t *testing.T) {
			repo, mock := newAccountVaultTestRepository(t)
			ids := []int64{17, 18}
			mock.ExpectBegin()
			rows := sqlmock.NewRows([]string{"id"}).AddRow(17)
			if !missing {
				rows.AddRow(18)
			}
			mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM account_vault WHERE id = ANY($1) ORDER BY id FOR UPDATE")).WithArgs(pq.Array(ids)).WillReturnRows(rows).RowsWillBeClosed()
			if missing {
				mock.ExpectRollback()
			} else {
				mock.ExpectExec(regexp.QuoteMeta("UPDATE account_vault SET group_name=$1, updated_at=NOW() WHERE id = ANY($2)")).WithArgs("新分组", pq.Array(ids)).WillReturnResult(sqlmock.NewResult(0, 2))
				mock.ExpectCommit()
			}
			err := repo.(service.AccountVaultGroupingRepository).AssignGroup(context.Background(), ids, "新分组")
			if missing {
				require.ErrorIs(t, err, service.ErrAccountVaultNotFound)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
