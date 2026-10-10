CREATE TABLE IF NOT EXISTS account_vault_automation (
 id SMALLINT PRIMARY KEY CHECK (id=1),
 actor_id BIGINT NOT NULL,
 token_version BIGINT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS account_vault_health (
 account_id BIGINT PRIMARY KEY REFERENCES account_vault(id) ON DELETE CASCADE,
 gateway_account_id BIGINT NOT NULL,
 status VARCHAR(32) NOT NULL DEFAULT 'unknown',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 checked_at TIMESTAMPTZ NOT NULL,
 quota JSONB,
 attempted_credential_hash VARCHAR(64) NOT NULL DEFAULT '',
 last_attempt_at TIMESTAMPTZ
);
COMMENT ON TABLE account_vault_health IS 'Read-only quota observations and bounded reauthorization state; contains no tokens, passwords, seeds or callback URLs';
