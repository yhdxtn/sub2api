package accountvault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

func sessionAAD(jobID, vaultID, email string) ([]byte, error) {
	if _, err := rotationAAD(jobID, vaultID, email); err != nil {
		return nil, err
	}
	return json.Marshal(struct{ Domain, JobID, VaultID, Email string }{"sub2api.accountvault.session.v1", jobID, vaultID, email})
}
func (c *Cipher) EncryptSession(jobID, vaultID, email string, data []byte) (string, error) {
	if c == nil || c.aead == nil || len(data) == 0 || len(data) > 524288 {
		return "", cipherError()
	}
	aad, err := sessionAAD(jobID, vaultID, email)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", cipherError()
	}
	sealed := c.aead.Seal(nonce, nonce, data, aad)
	defer clear(sealed)
	return "s1." + base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (c *Cipher) DecryptSession(jobID, vaultID, email, envelope string) ([]byte, error) {
	if c == nil || c.aead == nil || len(envelope) > 786432 || len(envelope) < 3 || envelope[:3] != "s1." {
		return nil, cipherError()
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(envelope[3:])
	defer clear(sealed)
	if err != nil || len(sealed) < c.aead.NonceSize()+c.aead.Overhead() {
		return nil, cipherError()
	}
	aad, err := sessionAAD(jobID, vaultID, email)
	if err != nil {
		return nil, err
	}
	n := c.aead.NonceSize()
	return c.aead.Open(nil, sealed[:n], sealed[n:], aad)
}
