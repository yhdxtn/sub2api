-- 管理员维护的外部账号与 TOTP 凭证库，与网关 accounts.credentials 完全独立。
-- encrypted_data 只接收应用层加密后的完整载荷，不存邮箱密码或 TOTP Secret 明文。
CREATE TABLE IF NOT EXISTS account_vault (
    id              BIGSERIAL PRIMARY KEY,
    vault_id        UUID NOT NULL UNIQUE,
    email           VARCHAR(320) NOT NULL UNIQUE,
    issuer          VARCHAR(256) NOT NULL DEFAULT '',
    has_password    BOOLEAN NOT NULL DEFAULT FALSE,
    algorithm       VARCHAR(6) NOT NULL DEFAULT 'SHA1',
    digits          SMALLINT NOT NULL DEFAULT 6,
    period          INTEGER NOT NULL DEFAULT 30,
    encrypted_data  TEXT NOT NULL,
    created_by      BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_vault_email_normalized CHECK (
        email <> '' AND email = LOWER(BTRIM(email))
    ),
    CONSTRAINT account_vault_algorithm_valid CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    CONSTRAINT account_vault_digits_valid CHECK (digits IN (6, 8)),
    CONSTRAINT account_vault_period_valid CHECK (period BETWEEN 1 AND 300),
    CONSTRAINT account_vault_ciphertext_present CHECK (LENGTH(BTRIM(encrypted_data)) > 0),
    CONSTRAINT account_vault_creator_valid CHECK (created_by >= 0)
);

COMMENT ON TABLE account_vault IS '管理员专用外部账号凭证库；禁止明文密码或 TOTP 密钥';
COMMENT ON COLUMN account_vault.encrypted_data IS '应用层认证加密载荷，数据库与仓库均不解密';
COMMENT ON COLUMN account_vault.created_by IS '导入管理员 ID，仅审计用途；不关联用户删除';

-- 单例指纹仅用于固定密钥绑定，不包含主密钥或可解密凭证。
-- 原子 INSERT ON CONFLICT 的无操作更新阻止不同密钥实例同时首次写入空库。
CREATE TABLE IF NOT EXISTS account_vault_metadata (
    id              SMALLINT PRIMARY KEY CHECK (id = 1),
    key_fingerprint CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_vault_key_fingerprint_valid CHECK (
        key_fingerprint ~ '^[0-9a-f]{64}$'
    )
);

COMMENT ON TABLE account_vault_metadata IS '账号库固定密钥指纹绑定；首次配置后不自动更换';
COMMENT ON COLUMN account_vault_metadata.key_fingerprint IS '域分离的密钥指纹，不是 AES 主密钥';
