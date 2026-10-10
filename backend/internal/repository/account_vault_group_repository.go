package repository

import (
	"context"
	"fmt"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

func (r *accountVaultRepository) Groups(ctx context.Context) ([]service.AccountVaultGroup, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT group_name, COUNT(*) FROM account_vault GROUP BY group_name ORDER BY group_name`)
	if err != nil {
		return nil, fmt.Errorf("list account vault groups: %w", err)
	}
	defer rows.Close()
	groups := make([]service.AccountVaultGroup, 0)
	for rows.Next() {
		var group service.AccountVaultGroup
		if err := rows.Scan(&group.Name, &group.Count); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// Lock the selected accounts in ID order and validate the entire batch before
// writing. A missing/deleted ID must not leave a partially regrouped selection.
func (r *accountVaultRepository) AssignGroup(ctx context.Context, ids []int64, name string) error {
	if err := r.ready(); err != nil {
		return err
	}
	if len(ids) == 0 || len(ids) > accountVaultMaxBatchSize {
		return fmt.Errorf("invalid account vault group batch")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM account_vault WHERE id = ANY($1) ORDER BY id FOR UPDATE`, pq.Array(ids))
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count != len(ids) {
		return service.ErrAccountVaultNotFound
	}
	if _, err = tx.ExecContext(ctx, `UPDATE account_vault SET group_name=$1, updated_at=NOW() WHERE id = ANY($2)`, name, pq.Array(ids)); err != nil {
		return err
	}
	return tx.Commit()
}
