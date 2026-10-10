package service

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/pkg/accountvault"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

type vaultGroupProbe struct {
	*accountVaultMemoryRepo
	assignedName string
	calls        int
}

func (r *vaultGroupProbe) AssignGroup(_ context.Context, ids []int64, name string) error {
	r.calls++
	r.assignedName = name
	for _, id := range ids {
		if _, ok := r.rows[id]; !ok {
			return ErrAccountVaultNotFound
		}
	}
	for _, id := range ids {
		row := r.rows[id]
		row.GroupName = name
		r.rows[id] = row
	}
	return nil
}
func (r *vaultGroupProbe) Groups(context.Context) ([]AccountVaultGroup, error) {
	return []AccountVaultGroup{{Name: r.assignedName, Count: int64(len(r.rows))}}, nil
}
func (r *vaultGroupProbe) ListByGroup(ctx context.Context, page, size int, search, group string) ([]AccountVaultRecord, int64, error) {
	rows, total, err := r.List(ctx, page, size, search)
	if group != r.assignedName {
		return []AccountVaultRecord{}, 0, nil
	}
	return rows, total, err
}

func TestAccountVaultGroupsPreserveCredentialsAndRotation(t *testing.T) {
	s, memory, _ := accountVaultTestService()
	probe := &vaultGroupProbe{accountVaultMemoryRepo: memory}
	s.repo = probe
	ctx := context.Background()
	imported, err := s.Import(ctx, 7, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("group@example.test")}})
	require.NoError(t, err)
	id := imported.Rows[0].ID
	before := memory.rows[id]
	require.NoError(t, s.AssignGroup(ctx, []int64{id}, "  工作组  "))
	require.Equal(t, "工作组", probe.assignedName)
	after := memory.rows[id]
	require.Equal(t, before.EncryptedData, after.EncryptedData)
	require.Equal(t, before.RotationState, after.RotationState)
	require.Equal(t, before.VaultID, after.VaultID)
	items, total, err := s.List(ctx, 1, 50, "", "工作组")
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Equal(t, "工作组", items[0].GroupName)
	require.NoError(t, s.AssignGroup(ctx, []int64{id}, ""))
	require.Empty(t, memory.rows[id].GroupName)
}

func TestAccountVaultGroupsValidateBeforeWriting(t *testing.T) {
	s, memory, _ := accountVaultTestService()
	probe := &vaultGroupProbe{accountVaultMemoryRepo: memory}
	s.repo = probe
	ctx := context.Background()
	for _, ids := range [][]int64{nil, {0}, {-1}, {1, 1}, make([]int64, 201)} {
		require.Error(t, s.AssignGroup(ctx, ids, "test"))
	}
	for _, name := range []string{strings.Repeat("组", 65), "a\x00b", "a\nb", string([]byte{0xff})} {
		require.Error(t, s.AssignGroup(ctx, []int64{1}, name))
	}
	require.Zero(t, probe.calls)
	require.ErrorIs(t, s.AssignGroup(ctx, []int64{404}, "test"), ErrAccountVaultNotFound)
}
