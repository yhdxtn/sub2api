package accountvault

import (
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestSessionCipherIsBoundToJobAndSeparatedFromRotation(t *testing.T) {
	cipher, err := NewCipher(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	require.NoError(t, err)
	job := "30000000-0000-4000-8000-000000000017"
	envelope, err := cipher.EncryptSession(job, "synthetic-vault", "test@example.test", []byte(`{"accessToken":"synthetic-canary"}`))
	require.NoError(t, err)
	require.NotContains(t, envelope, "synthetic-canary")
	opened, err := cipher.DecryptSession(job, "synthetic-vault", "test@example.test", envelope)
	require.NoError(t, err)
	require.Contains(t, string(opened), "synthetic-canary")
	_, err = cipher.DecryptSession("30000000-0000-4000-8000-000000000018", "synthetic-vault", "test@example.test", envelope)
	require.Error(t, err)
	_, err = cipher.DecryptRotation(job, "synthetic-vault", "test@example.test", envelope)
	require.Error(t, err)
}
