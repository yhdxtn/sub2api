package accountvault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Rotation encryption is purpose-separated from account credential envelopes.
// A ciphertext cannot be moved across jobs, accounts, emails or payload types.
func rotationAAD(jobID, vaultID, email string) ([]byte, error) {
	if len(jobID) != 36 || strings.TrimSpace(jobID) != jobID || unsafeText(jobID) {
		return nil, cipherError()
	}
	if _, err := associatedData(vaultID, email); err != nil {
		return nil, cipherError()
	}
	normalized, err := normalizeEmail(email)
	if err != nil || normalized != email {
		return nil, cipherError()
	}
	return json.Marshal(struct{ Domain, Version, JobID, VaultID, Email string }{"sub2api.accountvault.rotation.pending", "r1", jobID, vaultID, email})
}
func (c *Cipher) EncryptRotation(jobID, vaultID, email string, plaintext []byte) (string, error) {
	if c == nil || c.aead == nil || len(plaintext) == 0 || len(plaintext) > 16384 {
		return "", cipherError()
	}
	aad, err := rotationAAD(jobID, vaultID, email)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", cipherError()
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, aad)
	defer clear(sealed)
	return "r1." + base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (c *Cipher) DecryptRotation(jobID, vaultID, email, envelope string) ([]byte, error) {
	if c == nil || c.aead == nil || len(envelope) > 24576 {
		return nil, cipherError()
	}
	v, encoded, ok := strings.Cut(envelope, ".")
	if !ok || v != "r1" {
		return nil, cipherError()
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(sealed)
	if err != nil || base64.RawURLEncoding.EncodeToString(sealed) != encoded || len(sealed) < c.aead.NonceSize()+c.aead.Overhead() {
		return nil, cipherError()
	}
	aad, err := rotationAAD(jobID, vaultID, email)
	if err != nil {
		return nil, err
	}
	n := c.aead.NonceSize()
	plaintext, err := c.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, cipherError()
	}
	return plaintext, nil
}
