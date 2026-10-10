package accountvault

import (
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestRotationCipherPurposeAndIdentityIsolation(t *testing.T) {
	c, err := NewCipher(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))))
	require.NoError(t, err)
	const job = "10000000-0000-4000-8000-000000000001"
	const vault = "20000000-0000-4000-8000-000000000001"
	const email = "synthetic@example.test"
	plain := []byte(`{"secret":"synthetic-canary"}`)
	envelope, err := c.EncryptRotation(job, vault, email, plain)
	require.NoError(t, err)
	require.NotContains(t, envelope, string(plain))
	opened, err := c.DecryptRotation(job, vault, email, envelope)
	require.NoError(t, err)
	require.Equal(t, plain, opened)
	clear(opened)
	for _, ids := range [][3]string{{"10000000-0000-4000-8000-000000000002", vault, email}, {job, "other-vault", email}, {job, vault, "other@example.test"}} {
		_, err = c.DecryptRotation(ids[0], ids[1], ids[2], envelope)
		require.Error(t, err)
	}
	_, err = c.Decrypt(vault, email, envelope)
	require.Error(t, err)
	other, err := NewCipher(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	require.NoError(t, err)
	_, err = other.DecryptRotation(job, vault, email, envelope)
	require.Error(t, err)
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, "r1."))
	require.NoError(t, err)
	encoded[len(encoded)-1] ^= 1
	_, err = c.DecryptRotation(job, vault, email, "r1."+base64.RawURLEncoding.EncodeToString(encoded))
	require.Error(t, err)
}
