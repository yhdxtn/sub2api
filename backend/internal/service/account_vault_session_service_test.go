package service

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestVaultSessionSaveImportNeverMutatesSeedOrGrantsMFAPermit(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	j.Kind = "session"
	token := strings.Repeat("x", 43)
	j.LeaseHash = rotationHash(token)
	memory := &rotationUpdateMemory{job: j, record: r}
	s.repo = memory
	original := r.EncryptedData
	raw := json.RawMessage(`{"accessToken":"synthetic-access-canary","user":{"id":"synthetic-user","email":"rotation@example.test"}}`)
	normalize := func(raw json.RawMessage, email string) (json.RawMessage, error) {
		require.True(t, ValidateVaultSessionIdentity(raw, email))
		return json.RawMessage(`{"accounts":[{"name":"synthetic"}]}`), nil
	}
	saved, err := s.SaveSession(context.Background(), &AccountVaultWorkerGrant{ActorID: j.ActorID}, j.ID, token, j.Revision, raw, normalize)
	require.NoError(t, err)
	require.Equal(t, "prepared", saved.Phase)
	require.NotContains(t, memory.job.PendingEncrypted, "synthetic-access-canary")
	snapshot, err := s.openSession(memory.job, r)
	require.NoError(t, err)
	require.JSONEq(t, string(raw), string(snapshot.Session))
	_, _, _, err = s.transition(memory.job, r, AccountVaultRotationCheckpoint{Action: "disable"})
	require.ErrorIs(t, err, ErrVaultRotationInvalid)
	importer := func(_ context.Context, raw json.RawMessage, email string) (int64, json.RawMessage, error) {
		require.JSONEq(t, `{"accounts":[{"name":"synthetic"}]}`, string(raw))
		require.NotContains(t, string(raw), "synthetic-access-canary")
		return 42, json.RawMessage(`{"accounts":[{"name":"synthetic"}]}`), nil
	}
	completed, err := s.CompleteSession(context.Background(), &AccountVaultWorkerGrant{ActorID: j.ActorID}, j.ID, token, saved.Revision, importer)
	require.NoError(t, err)
	require.Equal(t, "completed", completed.Status)
	require.Equal(t, int64(42), completed.GatewayAccountID)
	require.Equal(t, original, memory.record.EncryptedData)
	require.Equal(t, "running", memory.record.RotationState)
	require.NotEmpty(t, memory.job.PendingEncrypted)
}

func TestVaultSessionAuthorizationBindsExchangeToEncryptedJobIntent(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	j.Kind = "session"
	token := strings.Repeat("x", 43)
	j.LeaseHash = rotationHash(token)
	memory := &rotationUpdateMemory{job: j, record: r}
	s.repo = memory
	grant := &AccountVaultWorkerGrant{ActorID: j.ActorID}
	raw := json.RawMessage(`{"accessToken":"synthetic-access-canary","user":{"id":"synthetic-user","email":"rotation@example.test"}}`)
	exchanged := false
	exchange := func(raw json.RawMessage, email, oauthID string) (json.RawMessage, error) {
		exchanged = true
		require.True(t, ValidateVaultSessionIdentity(raw, email))
		require.Equal(t, "synthetic-pkce-session", oauthID)
		return json.RawMessage(`{"accounts":[{"name":"synthetic"}]}`), nil
	}
	_, err := s.SaveAuthorizedSession(context.Background(), grant, j.ID, token, j.Revision, raw, exchange)
	require.Error(t, err)
	require.False(t, exchanged)
	started, authURL, err := s.BeginSessionAuthorization(context.Background(), grant, j.ID, token, j.Revision, func() (string, string, error) {
		return "synthetic-pkce-session", "https://auth.openai.com/oauth/authorize", nil
	})
	require.NoError(t, err)
	require.Equal(t, "https://auth.openai.com/oauth/authorize", authURL)
	require.NotContains(t, memory.job.PendingEncrypted, "synthetic-pkce-session")
	_, err = s.SaveAuthorizedSession(context.Background(), grant, j.ID, token, j.Revision, raw, exchange)
	require.Error(t, err) // stale revision cannot consume a provider authorization code
	require.False(t, exchanged)
	_, err = s.SaveAuthorizedSession(context.Background(), grant, j.ID, token, started.Revision, raw, exchange)
	require.NoError(t, err)
	require.True(t, exchanged)
	require.Equal(t, r.EncryptedData, memory.record.EncryptedData)
}

func TestVaultOAuthOnlyExchangeIsFencedAndImportsWithoutWebSession(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	j.Kind = "session"
	token := strings.Repeat("x", 43)
	j.LeaseHash = rotationHash(token)
	memory := &rotationUpdateMemory{job: j, record: r}
	s.repo = memory
	grant := &AccountVaultWorkerGrant{ActorID: j.ActorID}
	exchanged := false
	exchange := func(email, oauthID string) (json.RawMessage, error) {
		exchanged = true
		require.Equal(t, r.Email, email)
		require.Equal(t, "synthetic-pkce-session", oauthID)
		return json.RawMessage(`{"accounts":[{"credentials":{"access_token":"synthetic-oauth-canary"}}]}`), nil
	}
	_, err := s.SaveOAuthAuthorization(context.Background(), grant, j.ID, token, j.Revision, exchange)
	require.Error(t, err)
	require.False(t, exchanged)
	started, _, err := s.BeginSessionAuthorization(context.Background(), grant, j.ID, token, j.Revision, func() (string, string, error) {
		return "synthetic-pkce-session", "https://auth.openai.com/oauth/authorize", nil
	})
	require.NoError(t, err)
	_, err = s.SaveOAuthAuthorization(context.Background(), grant, j.ID, token, j.Revision, exchange)
	require.Error(t, err)
	require.False(t, exchanged)
	saved, err := s.SaveOAuthAuthorization(context.Background(), grant, j.ID, token, started.Revision, exchange)
	require.NoError(t, err)
	require.True(t, exchanged)
	snapshot, err := s.openSession(memory.job, r)
	require.NoError(t, err)
	require.Equal(t, "null", string(snapshot.Session))
	require.NotContains(t, memory.job.PendingEncrypted, "synthetic-oauth-canary")
	completed, err := s.CompleteSession(context.Background(), grant, j.ID, token, saved.Revision, func(_ context.Context, raw json.RawMessage, email string) (int64, json.RawMessage, error) {
		require.Contains(t, string(raw), "synthetic-oauth-canary")
		return 42, raw, nil
	})
	require.NoError(t, err)
	require.Equal(t, "completed", completed.Status)
	require.Equal(t, r.EncryptedData, memory.record.EncryptedData)
}
