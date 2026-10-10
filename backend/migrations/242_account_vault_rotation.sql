-- Durable first-import ChatGPT TOTP replacement. No browser cookies or raw API responses are stored.
ALTER TABLE account_vault ADD COLUMN rotation_state VARCHAR(24) NOT NULL DEFAULT 'required';
ALTER TABLE account_vault ADD COLUMN rotation_phase VARCHAR(24) NOT NULL DEFAULT '';
ALTER TABLE account_vault ADD COLUMN rotation_completed_at TIMESTAMPTZ;
ALTER TABLE account_vault ADD CONSTRAINT account_vault_rotation_state_valid CHECK (rotation_state IN ('required','queued','running','paused','completed','cancelled','blocked'));

CREATE TABLE account_vault_rotation_jobs (
 id UUID PRIMARY KEY,
 account_id BIGINT NOT NULL REFERENCES account_vault(id) ON DELETE RESTRICT,
 actor_id BIGINT NOT NULL,
 provider VARCHAR(24) NOT NULL DEFAULT 'chatgpt' CHECK (provider = 'chatgpt'),
 status VARCHAR(16) NOT NULL CHECK (status IN ('queued','running','paused','completed','cancelled')),
 phase VARCHAR(24) NOT NULL CHECK (phase IN ('login','prepared','disable_intent','disabled','enroll_intent','enrolled','activate_intent','verified','completed')),
 revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
 progress VARCHAR(40) NOT NULL DEFAULT 'queued',
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 pending_encrypted TEXT NOT NULL DEFAULT '',
 subject_hash VARCHAR(64) NOT NULL DEFAULT '',
 base_cipher_hash CHAR(64) NOT NULL,
 lease_hash VARCHAR(64) NOT NULL DEFAULT '',
 lease_expires_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 completed_at TIMESTAMPTZ,
 CHECK (subject_hash = '' OR subject_hash ~ '^[0-9a-f]{64}$'),
 CHECK (lease_hash = '' OR lease_hash ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX account_vault_rotation_one_active ON account_vault_rotation_jobs(account_id) WHERE status IN ('queued','running','paused');
CREATE UNIQUE INDEX account_vault_rotation_one_running_actor ON account_vault_rotation_jobs(actor_id) WHERE status = 'running';
CREATE UNIQUE INDEX account_vault_rotation_one_subject ON account_vault_rotation_jobs(provider,subject_hash) WHERE subject_hash <> '' AND status IN ('queued','running','paused');
CREATE INDEX account_vault_rotation_actor_queue ON account_vault_rotation_jobs(actor_id,status,created_at);

CREATE TABLE account_vault_rotation_events (
 id BIGSERIAL PRIMARY KEY,
 job_id UUID NOT NULL REFERENCES account_vault_rotation_jobs(id) ON DELETE CASCADE,
 revision BIGINT NOT NULL,
 phase VARCHAR(24) NOT NULL,
 event VARCHAR(64) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- This ledger deliberately survives deleting the account and its jobs.
CREATE TABLE account_vault_rotation_ledger (
 provider VARCHAR(24) NOT NULL,
 email VARCHAR(320) NOT NULL,
 subject_hash CHAR(64) NOT NULL,
 completed_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(provider,email),
 UNIQUE(provider,subject_hash)
);
CREATE TABLE account_vault_worker_tokens (
 id UUID PRIMARY KEY,
 actor_id BIGINT NOT NULL,
 token_version BIGINT NOT NULL,
 token_hash CHAR(64) NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 revoked BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX account_vault_worker_tokens_actor ON account_vault_worker_tokens(actor_id);
COMMENT ON COLUMN account_vault_rotation_jobs.pending_encrypted IS 'Dedicated-purpose AES-GCM envelope; enrollment secret/session/remote identities never stored plaintext';
COMMENT ON TABLE account_vault_rotation_ledger IS 'Permanent first-completion guard, preserved across vault account deletion/reimport';
