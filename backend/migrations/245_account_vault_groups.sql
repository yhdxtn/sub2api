-- Vault grouping is metadata and does not modify encrypted credentials or OAuth accounts.
ALTER TABLE account_vault ADD COLUMN IF NOT EXISTS group_name VARCHAR(64) NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_account_vault_group_name_id ON account_vault (group_name, id DESC);
COMMENT ON COLUMN account_vault.group_name IS '账号库分组名称；空字符串表示未分组';
