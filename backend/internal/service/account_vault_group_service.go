package service

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

func normalizeVaultGroup(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 64 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_GROUP", "分组名称最多 64 个字符，不能包含控制字符")
	}
	return name, nil
}

func (s *AccountVaultService) Groups(ctx context.Context) ([]AccountVaultGroup, error) {
	if err := s.checkKey(ctx); err != nil {
		return nil, err
	}
	repo, ok := s.repo.(AccountVaultGroupingRepository)
	if !ok {
		return nil, vaultStorageError()
	}
	groups, err := repo.Groups(ctx)
	if err != nil {
		return nil, vaultStorageError()
	}
	return groups, nil
}

func (s *AccountVaultService) AssignGroup(ctx context.Context, ids []int64, name string) error {
	if len(ids) == 0 || len(ids) > AccountVaultMaxCodeRows {
		return infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_IDS", "请选择 1～200 个账号")
	}
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return infraerrors.BadRequest("ACCOUNT_VAULT_INVALID_IDS", "账号编号无效或重复")
		}
		seen[id] = true
	}
	name, err := normalizeVaultGroup(name)
	if err != nil {
		return err
	}
	if err := s.checkKey(ctx); err != nil {
		return err
	}
	repo, ok := s.repo.(AccountVaultGroupingRepository)
	if !ok {
		return vaultStorageError()
	}
	if err := repo.AssignGroup(ctx, ids, name); err != nil {
		if errors.Is(err, ErrAccountVaultNotFound) {
			return err
		}
		return vaultStorageError()
	}
	return nil
}
