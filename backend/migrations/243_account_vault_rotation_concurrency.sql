CREATE TABLE account_vault_rotation_settings (
    actor_id BIGINT PRIMARY KEY,
    concurrency SMALLINT NOT NULL DEFAULT 2 CHECK (concurrency BETWEEN 1 AND 4),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP INDEX IF EXISTS account_vault_rotation_one_running_actor;
CREATE INDEX account_vault_rotation_running_actor ON account_vault_rotation_jobs(actor_id) WHERE status='running';
