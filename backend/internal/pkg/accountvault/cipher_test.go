package accountvault

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func fixtureCipher(t *testing.T, character byte) *Cipher {
	t.Helper()
	value := make([]byte, 32)
	for index := range value {
		value[index] = character
	}
	cipher, err := NewCipher(base64.StdEncoding.EncodeToString(value))
	clear(value)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestCipherRoundTripRandomNonceAndBoundIdentity(t *testing.T) {
	cipher := fixtureCipher(t, 'k')
	input := sampleInput()
	input.Email, input.Algorithm, input.Digits, input.Period = "USER@EXAMPLE.TEST", "SHA256", 8, 60
	expected, _ := Normalize(input)
	first, err := cipher.Encrypt("vault-row-one", input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cipher.Encrypt("vault-row-one", input)
	if err != nil || first == second || !strings.HasPrefix(first, "v1.") {
		t.Fatal("encryption must use a fresh nonce for every record write")
	}
	if strings.Contains(first, input.Password) || strings.Contains(first, input.Secret) {
		t.Fatal("plaintext credentials appeared in the persisted envelope")
	}
	got, err := cipher.Decrypt("vault-row-one", "user@example.test", first)
	if err != nil || got != expected {
		t.Fatal("encrypted credentials did not round-trip exactly")
	}
	if _, err := cipher.Decrypt("vault-row-one", "USER@EXAMPLE.TEST", first); err != nil {
		t.Fatal("canonical email identity should be case independent")
	}
	for _, id := range []string{"vault-row-two", "", "vault-row-one\x00other"} {
		if _, err := cipher.Decrypt(id, expected.Email, first); err == nil {
			t.Fatal("ciphertext could be moved to another row identity")
		}
	}
	if _, err := cipher.Decrypt("vault-row-one", "other@example.test", first); err == nil {
		t.Fatal("ciphertext could be moved to another email identity")
	}
	if _, err := fixtureCipher(t, 'x').Decrypt("vault-row-one", expected.Email, first); err == nil {
		t.Fatal("a wrong AES key could decrypt the record")
	}
}

func TestCipherTamperingAndVersionRejection(t *testing.T) {
	cipher := fixtureCipher(t, 'k')
	input := sampleInput()
	envelope, err := cipher.Encrypt("row", input)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, "v1."))
	defer clear(raw)
	for _, index := range []int{0, 12, len(raw) - 1} {
		changed := append([]byte(nil), raw...)
		changed[index] ^= 1
		value := "v1." + base64.RawURLEncoding.EncodeToString(changed)
		clear(changed)
		if _, err := cipher.Decrypt("row", input.Email, value); err == nil {
			t.Fatal("tampered nonce, payload, or tag was accepted")
		}
	}
	for _, bad := range []string{"", "v1.", "v1.invalid!", "v1.AA", "v2." + strings.TrimPrefix(envelope, "v1."), envelope + "=", strings.Repeat("x", 16385)} {
		if _, err := cipher.Decrypt("row", input.Email, bad); err == nil {
			t.Fatal("invalid ciphertext envelope was accepted")
		} else if strings.Contains(err.Error(), publicSeed) || strings.Contains(err.Error(), input.Password) {
			t.Fatal("decryption error leaked plaintext credentials")
		}
	}
}

func TestCipherConfigurationAndImportValidation(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33} {
		if _, err := NewCipher(base64.StdEncoding.EncodeToString(make([]byte, size))); err == nil {
			t.Fatal("AES key must be exactly 32 bytes")
		}
	}
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, key := range []string{valid + "\n", " " + valid, strings.TrimRight(valid, "="), "not-a-key"} {
		if _, err := NewCipher(key); err == nil {
			t.Fatal("noncanonical key encoding was accepted")
		}
	}
	cipher := fixtureCipher(t, 'k')
	input := sampleInput()
	input.Email = ""
	if _, err := cipher.Encrypt("row", input); err == nil {
		t.Fatal("email-free QR previews must never be persisted")
	}
	var nilCipher *Cipher
	if _, err := nilCipher.Encrypt("row", sampleInput()); err == nil {
		t.Fatal("unconfigured encryption should fail closed")
	}
}

func TestCipherSupportsConcurrentIndependentRecords(t *testing.T) {
	cipher := fixtureCipher(t, 'k')
	input, _ := Normalize(sampleInput())
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			sealed, err := cipher.Encrypt("concurrent-row", input)
			if err != nil {
				t.Error("concurrent encrypt failed")
				return
			}
			decoded, err := cipher.Decrypt("concurrent-row", input.Email, sealed)
			if err != nil || decoded != input {
				t.Error("concurrent decrypt failed")
			}
		}()
	}
	group.Wait()
}

func TestCipherKeyFingerprintBindsDeploymentKeyWithoutExposingIt(t *testing.T) {
	first := fixtureCipher(t, 'k')
	same := fixtureCipher(t, 'k')
	other := fixtureCipher(t, 'x')
	fingerprint := first.KeyFingerprint()
	const expected = "84bd94f4fa48d86b03daf51240ef48f5c3a6b7e0eceee2d962d09f0262b8173b"
	if fingerprint != expected || fingerprint != same.KeyFingerprint() || fingerprint == other.KeyFingerprint() {
		t.Fatal("the versioned deployment fingerprint must be stable and key-specific")
	}
	raw, err := hex.DecodeString(fingerprint)
	defer clear(raw)
	if err != nil || len(raw) != 32 || fingerprint != strings.ToLower(fingerprint) {
		t.Fatal("the fingerprint must be canonical lowercase SHA-256 hex")
	}
	key := strings.Repeat("k", 32)
	if string(raw) == key || strings.Contains(fingerprint, key) || fingerprint == hex.EncodeToString([]byte(key)) || fingerprint == base64.StdEncoding.EncodeToString([]byte(key)) {
		t.Fatal("the fingerprint must not retain or encode the original key")
	}
	encoded, err := json.Marshal(first)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("cipher internals and the fingerprint must not be JSON API fields")
	}
	var absent *Cipher
	if absent.KeyFingerprint() != "" || (&Cipher{}).KeyFingerprint() != "" {
		t.Fatal("an unconfigured cipher must not bind a deployment fingerprint")
	}
}

func TestCipherRejectsAuthenticatedButAmbiguousJSONPayload(t *testing.T) {
	cipher := fixtureCipher(t, 'k')
	const email = "demo@example.test"
	aad, err := associatedData("row", email)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`,"period":null`, `,"Email":"other@example.test"`, `,"email":"other@example.test"`, `,"digits":"6"`} {
		plaintext := []byte(`{"email":"` + email + `","secret":"` + publicSeed + `"` + extra + `}`)
		nonce := make([]byte, cipher.aead.NonceSize())
		sealed := cipher.aead.Seal(nonce, nonce, plaintext, aad)
		envelope := envelopeVersion + "." + base64.RawURLEncoding.EncodeToString(sealed)
		clear(plaintext)
		clear(sealed)
		if _, err := cipher.Decrypt("row", email, envelope); err == nil {
			t.Fatal("authenticated ciphertext must still satisfy strict Input JSON rules")
		}
	}
}
