package accountvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

const envelopeVersion = "v1"
const keyFingerprintDomain = "sub2api.accountvault.key-check.v1"

type Cipher struct {
	aead           cipher.AEAD
	keyFingerprint string
}

func cipherError() error {
	return errors.New("账号加密数据无法验证，可能已损坏或使用了错误的密钥。")
}

// NewCipher requires one canonical, standard Base64-encoded 32-byte AES key.
// It intentionally never derives a key from a short password or generates a
// silent replacement for a missing deployment key.
func NewCipher(base64Key string) (*Cipher, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(base64Key)
	defer clear(key)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != base64Key {
		return nil, errors.New("账号加密密钥必须是规范 Base64 编码的 32 字节随机密钥。")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, cipherError()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, cipherError()
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(keyFingerprintDomain))
	fingerprint := mac.Sum(nil)
	defer clear(fingerprint)
	return &Cipher{aead: aead, keyFingerprint: hex.EncodeToString(fingerprint)}, nil
}

// KeyFingerprint is a domain-separated key check for atomically binding one
// deployment key to vault metadata. It must not be exposed in API responses.
// Only the derived value is retained alongside the AES cipher, never another
// copy of the original key. An unconfigured cipher returns no fingerprint.
func (c *Cipher) KeyFingerprint() string {
	if c == nil || c.aead == nil {
		return ""
	}
	return c.keyFingerprint
}

func associatedData(vaultID, email string) ([]byte, error) {
	if vaultID == "" || len(vaultID) > 256 || unsafeText(vaultID) || strings.TrimSpace(vaultID) != vaultID {
		return nil, errors.New("账号存储标识格式不正确。")
	}
	// JSON encoding keeps all fields unambiguous. AAD binds format version,
	// application domain, database row identity, and canonical email address.
	return json.Marshal(struct {
		Domain  string `json:"domain"`
		Version string `json:"version"`
		VaultID string `json:"vault_id"`
		Email   string `json:"email"`
	}{"sub2api.accountvault", envelopeVersion, vaultID, email})
}

func (c *Cipher) Encrypt(vaultID string, input Input) (string, error) {
	if c == nil || c.aead == nil {
		return "", cipherError()
	}
	input, err := Normalize(input)
	if err != nil {
		return "", err
	}
	aad, err := associatedData(vaultID, input.Email)
	if err != nil {
		return "", err
	}
	plaintext, err := json.Marshal(input)
	if err != nil {
		return "", cipherError()
	}
	defer clear(plaintext)
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", cipherError()
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, aad)
	defer clear(sealed)
	return envelopeVersion + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *Cipher) Decrypt(vaultID, email, ciphertext string) (Input, error) {
	if c == nil || c.aead == nil || len(ciphertext) > 16*1024 {
		return Input{}, cipherError()
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return Input{}, cipherError()
	}
	version, encoded, found := strings.Cut(ciphertext, ".")
	if !found || version != envelopeVersion {
		return Input{}, cipherError()
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(sealed)
	if err != nil || len(sealed) < c.aead.NonceSize()+c.aead.Overhead() || base64.RawURLEncoding.EncodeToString(sealed) != encoded {
		return Input{}, cipherError()
	}
	aad, err := associatedData(vaultID, email)
	if err != nil {
		return Input{}, cipherError()
	}
	nonceSize := c.aead.NonceSize()
	plaintext, err := c.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return Input{}, cipherError()
	}
	defer clear(plaintext)
	// The encrypted payload is validated independently of its authenticity, so
	// unsupported fields or parameters cannot silently enter later OTP calls.
	var input Input
	if json.Unmarshal(plaintext, &input) != nil {
		return Input{}, cipherError()
	}
	input, err = Normalize(input)
	if err != nil || input.Email != email {
		return Input{}, cipherError()
	}
	return input, nil
}
