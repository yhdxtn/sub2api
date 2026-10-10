ALTER TABLE account_vault_rotation_jobs ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'rotation' CHECK (kind IN ('rotation','session'));
ALTER TABLE account_vault_rotation_jobs ADD COLUMN gateway_account_id BIGINT NOT NULL DEFAULT 0;
COMMENT ON COLUMN account_vault_rotation_jobs.kind IS 'Session acquisition shares leases/capacity with rotation but never changes vault credentials or MFA';
