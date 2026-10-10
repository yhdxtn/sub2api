package service

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/accountvault"
	"github.com/stretchr/testify/require"
)

// All identities, secrets and password strings below are synthetic test data.
func rotationTestSetup(t *testing.T) (*AccountVaultRotationService, AccountVaultRotationJob, AccountVaultRecord) {
	t.Helper()
	c, err := accountvault.NewCipher(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	require.NoError(t, err)
	input := accountvault.Input{Email: "rotation@example.test", Password: "synthetic-password", Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("synthetic-old-key-20!")), Issuer: "Synthetic", Algorithm: "SHA256", Digits: 8, Period: 45}
	record := AccountVaultRecord{ID: 7, VaultID: "10000000-0000-4000-8000-000000000007", Email: input.Email, Issuer: input.Issuer, HasPassword: true, Algorithm: input.Algorithm, Digits: input.Digits, Period: input.Period, RotationState: "running", RotationPhase: "login"}
	record.EncryptedData, err = c.Encrypt(record.VaultID, input)
	require.NoError(t, err)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := &AccountVaultRotationService{vault: &AccountVaultService{cipher: c}, now: func() time.Time { return now }}
	job := AccountVaultRotationJob{ID: "20000000-0000-4000-8000-000000000007", AccountID: 7, ActorID: 9, Provider: VaultRotationProvider, Status: "running", Phase: "login", Revision: 2, Progress: "login", BaseCipherHash: rotationHash(record.EncryptedData), CreatedAt: now, UpdatedAt: now}
	return s, job, record
}
func rotationTestObservation(enabled bool, id string) AccountVaultRotationCheckpoint {
	ids := []string{}
	if id != "" {
		ids = append(ids, id)
	}
	return AccountVaultRotationCheckpoint{Identity: &AccountVaultRotationIdentity{ID: "synthetic-upstream", Email: "rotation@example.test"}, MFA: &AccountVaultRotationMFA{Enabled: enabled, EnabledV2: enabled, DefaultFactorID: id, TOTPFactorIDs: ids}}
}
func rotationTestEnrollment() *AccountVaultRotationEnrollment {
	return &AccountVaultRotationEnrollment{Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("synthetic-new-key-20!")), SessionID: "synthetic-session", FactorID: "synthetic-new-factor", FactorType: "totp"}
}
func advanceRotation(t *testing.T, s *AccountVaultRotationService, j AccountVaultRotationJob, r AccountVaultRecord, action string) AccountVaultRotationJob {
	t.Helper()
	req := AccountVaultRotationCheckpoint{Action: action}
	switch action {
	case "prepared":
		req = rotationTestObservation(true, "synthetic-old-factor")
		req.Action = action
	case "disabled":
		req = rotationTestObservation(false, "")
		req.Action = action
	case "enrolled":
		req.Enrollment = rotationTestEnrollment()
	}
	mutation, _, _, err := s.transition(j, r, req)
	require.NoError(t, err)
	return mutation.Job
}
func TestAccountVaultRotationPersistsNewCredentialBeforeActivationAndPreservesPassword(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	original := r.EncryptedData
	for _, action := range []string{"prepared", "disable", "disabled", "enroll", "enrolled"} {
		j = advanceRotation(t, s, j, r, action)
	}
	require.Equal(t, "enrolled", j.Phase)
	require.NotContains(t, j.PendingEncrypted, rotationTestEnrollment().Secret)
	require.Equal(t, original, r.EncryptedData)
	pending, err := s.openPending(j, r)
	require.NoError(t, err)
	require.Equal(t, rotationTestEnrollment().Secret, pending.Secret)
	// Public progress never contains remote IDs, session IDs or the pending seed.
	raw, err := json.Marshal(j.Public())
	require.NoError(t, err)
	for _, v := range []string{pending.Secret, pending.SessionID, pending.UpstreamID, pending.OldFactorID, pending.NewFactorID} {
		require.NotContains(t, string(raw), v)
	}
	mutation, permit, _, err := s.transition(j, r, AccountVaultRotationCheckpoint{Action: "activate"})
	require.NoError(t, err)
	require.Equal(t, "activate", permit)
	j = mutation.Job
	req := rotationTestObservation(true, "synthetic-new-factor")
	req.Action = "verify"
	mutation, _, _, err = s.transition(j, r, req)
	require.NoError(t, err)
	require.True(t, mutation.Complete)
	require.Empty(t, mutation.Job.PendingEncrypted)
	require.Equal(t, "completed", mutation.Job.Status)
	saved, err := s.vault.cipher.Decrypt(r.VaultID, r.Email, mutation.NewEncryptedData)
	require.NoError(t, err)
	require.Equal(t, "synthetic-password", saved.Password)
	require.Equal(t, "Synthetic", saved.Issuer)
	require.Equal(t, pending.Secret, saved.Secret)
	require.Equal(t, "SHA1", saved.Algorithm)
	require.Equal(t, 6, saved.Digits)
	require.Equal(t, 30, saved.Period)
}
func TestAccountVaultRotationRejectsInsufficientFinalProof(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	for _, action := range []string{"prepared", "disable", "disabled", "enroll", "enrolled", "activate"} {
		j = advanceRotation(t, s, j, r, action)
	}
	cases := map[string]func(*AccountVaultRotationCheckpoint){
		"wrong_email":     func(q *AccountVaultRotationCheckpoint) { q.Identity.Email = "other@example.test" },
		"changed_subject": func(q *AccountVaultRotationCheckpoint) { q.Identity.ID = "other-subject" },
		"v1_false":        func(q *AccountVaultRotationCheckpoint) { q.MFA.Enabled = false },
		"v2_false":        func(q *AccountVaultRotationCheckpoint) { q.MFA.EnabledV2 = false },
		"old_default":     func(q *AccountVaultRotationCheckpoint) { q.MFA.DefaultFactorID = "synthetic-old-factor" },
		"old_still_present": func(q *AccountVaultRotationCheckpoint) {
			q.MFA.TOTPFactorIDs = append(q.MFA.TOTPFactorIDs, "synthetic-old-factor")
		},
		"unrelated_extra_factor": func(q *AccountVaultRotationCheckpoint) {
			q.MFA.TOTPFactorIDs = append(q.MFA.TOTPFactorIDs, "synthetic-extra-factor")
		},
		"missing_factor":      func(q *AccountVaultRotationCheckpoint) { q.MFA.TOTPFactorIDs = []string{} },
		"missing_observation": func(q *AccountVaultRotationCheckpoint) { q.MFA = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			q := rotationTestObservation(true, "synthetic-new-factor")
			q.Action = "verify"
			change(&q)
			mutation, permit, _, err := s.transition(j, r, q)
			require.Error(t, err)
			require.Empty(t, permit)
			require.Empty(t, mutation.NewEncryptedData)
			require.False(t, mutation.Complete)
		})
	}
}
func TestAccountVaultRotationIntentCannotBeReplayedOrRewound(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	j = advanceRotation(t, s, j, r, "prepared")
	j = advanceRotation(t, s, j, r, "disable")
	for _, action := range []string{"disable", "prepared", "enroll", "activate", "verify"} {
		_, permit, _, err := s.transition(j, r, AccountVaultRotationCheckpoint{Action: action})
		require.Error(t, err)
		require.Empty(t, permit)
	}
	j = advanceRotation(t, s, j, r, "disabled")
	j = advanceRotation(t, s, j, r, "enroll")
	_, permit, _, err := s.transition(j, r, AccountVaultRotationCheckpoint{Action: "enroll"})
	require.Error(t, err)
	require.Empty(t, permit)
	dto := j
	dto.Status = "paused"
	require.False(t, dto.Public().CanResume)
	require.False(t, dto.Public().CanCancel)
}
func TestAccountVaultRotationEnrollmentAndAccountSnapshotGuards(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	for _, action := range []string{"prepared", "disable", "disabled", "enroll"} {
		j = advanceRotation(t, s, j, r, action)
	}
	for _, change := range []func(*AccountVaultRotationEnrollment){func(e *AccountVaultRotationEnrollment) { e.Secret = "invalid!" }, func(e *AccountVaultRotationEnrollment) { e.SessionID = "" }, func(e *AccountVaultRotationEnrollment) { e.FactorID = "synthetic-old-factor" }, func(e *AccountVaultRotationEnrollment) { e.FactorType = "sms" }} {
		e := rotationTestEnrollment()
		change(e)
		m, _, _, err := s.transition(j, r, AccountVaultRotationCheckpoint{Action: "enrolled", Enrollment: e})
		require.Error(t, err)
		require.Empty(t, m.Job.PendingEncrypted)
	}
	r.EncryptedData = "concurrently-replaced-ciphertext"
	_, _, _, err := s.transition(j, r, AccountVaultRotationCheckpoint{Action: "enrolled", Enrollment: rotationTestEnrollment()})
	require.ErrorIs(t, err, ErrVaultRotationConflict)
}

type rotationUpdateMemory struct {
	AccountVaultRotationRepository
	job    AccountVaultRotationJob
	record AccountVaultRecord
	fail   bool
}

func (m *rotationUpdateMemory) Update(_ context.Context, actorID int64, id string, f *AccountVaultRotationFence, fn AccountVaultRotationUpdate) (*AccountVaultRotationJob, error) {
	if actorID != m.job.ActorID || id != m.job.ID {
		return nil, ErrVaultRotationNotFound
	}
	if f != nil && (f.LeaseHash != m.job.LeaseHash || f.Revision != m.job.Revision) {
		return nil, ErrVaultRotationConflict
	}
	mutation, err := fn(m.job, m.record)
	if err != nil {
		return nil, err
	}
	if m.fail {
		return nil, errors.New("synthetic storage failure with private-data-canary")
	}
	m.job = mutation.Job
	j := m.job
	return &j, nil
}
func TestAccountVaultRotationFailedPersistenceNeverReturnsPermit(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	j = advanceRotation(t, s, j, r, "prepared")
	token := strings.Repeat("x", 43)
	j.LeaseHash = rotationHash(token)
	memory := &rotationUpdateMemory{job: j, record: r, fail: true}
	s.repo = memory
	result, err := s.Checkpoint(context.Background(), &AccountVaultWorkerGrant{ActorID: j.ActorID}, j.ID, AccountVaultRotationCheckpoint{LeaseToken: token, Revision: j.Revision, Action: "disable"})
	require.Error(t, err)
	require.Nil(t, result)
	require.NotContains(t, err.Error(), "private-data-canary")
	require.Equal(t, "prepared", memory.job.Phase)
	for _, action := range []string{"disable", "disabled", "enroll"} {
		j = advanceRotation(t, s, j, r, action)
	}
	j.LeaseHash = rotationHash(token)
	memory.job = j
	result, err = s.Checkpoint(context.Background(), &AccountVaultWorkerGrant{ActorID: j.ActorID}, j.ID, AccountVaultRotationCheckpoint{LeaseToken: token, Revision: j.Revision, Action: "enrolled", Enrollment: rotationTestEnrollment()})
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, "enroll_intent", memory.job.Phase)
	code, err := s.Code(context.Background(), &AccountVaultWorkerGrant{ActorID: j.ActorID}, j.ID, token, j.Revision, true)
	require.Error(t, err)
	require.Nil(t, code)
}

type rotationTokenMemory struct {
	AccountVaultRotationRepository
	token *AccountVaultWorkerToken
}

func (m *rotationTokenMemory) FindToken(_ context.Context, hash string) (*AccountVaultWorkerToken, error) {
	if m.token == nil || m.token.Hash != hash {
		return nil, ErrVaultWorkerUnauthorized
	}
	return m.token, nil
}

type rotationUsers struct {
	UserRepository
	user  *User
	calls int
}

func (u *rotationUsers) GetByID(_ context.Context, id int64) (*User, error) {
	u.calls++
	if u.user == nil || u.user.ID != id {
		return nil, errors.New("missing")
	}
	copy := *u.user
	return &copy, nil
}
func TestAccountVaultRotationWorkerChecksCurrentAdministratorEveryRequest(t *testing.T) {
	s, _, _ := rotationTestSetup(t)
	s.vault.keyVerified = true
	token := "avw1_" + strings.Repeat("x", 43)
	users := &rotationUsers{user: &User{ID: 9, Email: "admin@example.test", PasswordHash: "synthetic-hash", Role: RoleAdmin, Status: StatusActive}}
	s.users = users
	row := &AccountVaultWorkerToken{ID: "token-test", ActorID: 9, TokenVersion: resolvedTokenVersion(users.user), Hash: rotationHash(token), ExpiresAt: s.now().Add(time.Hour)}
	repo := &rotationTokenMemory{token: row}
	s.repo = repo
	_, err := s.AuthenticateWorker(context.Background(), token)
	require.NoError(t, err)
	users.user.Role = RoleUser
	_, err = s.AuthenticateWorker(context.Background(), token)
	require.ErrorIs(t, err, ErrVaultWorkerUnauthorized)
	users.user.Role = RoleAdmin
	users.user.Status = "disabled"
	_, err = s.AuthenticateWorker(context.Background(), token)
	require.ErrorIs(t, err, ErrVaultWorkerUnauthorized)
	users.user.Status = StatusActive
	users.user.PasswordHash = "changed-synthetic-hash"
	_, err = s.AuthenticateWorker(context.Background(), token)
	require.ErrorIs(t, err, ErrVaultWorkerUnauthorized)
	users.user.PasswordHash = "synthetic-hash"
	row.Revoked = true
	_, err = s.AuthenticateWorker(context.Background(), token)
	require.ErrorIs(t, err, ErrVaultWorkerUnauthorized)
	row.Revoked = false
	row.ExpiresAt = s.now()
	_, err = s.AuthenticateWorker(context.Background(), token)
	require.ErrorIs(t, err, ErrVaultWorkerUnauthorized)
	require.GreaterOrEqual(t, users.calls, 4)
}

func TestAccountVaultRotationRecoveryLoginCodeByPhase(t *testing.T) {
	s, j, r := rotationTestSetup(t)
	token := strings.Repeat("x", 43)
	j.LeaseHash = rotationHash(token)
	m := &rotationUpdateMemory{job: j, record: r}
	s.repo = m
	grant := &AccountVaultWorkerGrant{ActorID: j.ActorID}
	old, err := s.vault.open(r)
	require.NoError(t, err)
	oldCode, err := accountvault.GenerateCode(old, s.now())
	require.NoError(t, err)
	for _, action := range []string{"", "prepared", "disable", "disabled", "enroll", "enrolled", "activate"} {
		if action != "" {
			j = advanceRotation(t, s, j, r, action)
		}
		m.job = j
		code, err := s.Code(context.Background(), grant, j.ID, token, j.Revision, false)
		switch j.Phase {
		case "disabled", "enroll_intent":
			require.Error(t, err)
			require.Nil(t, code)
		case "login", "prepared", "disable_intent":
			require.NoError(t, err)
			require.Equal(t, oldCode.Code, code.Code.Code)
			require.Empty(t, code.SessionID)
			require.Empty(t, code.FactorID)
		default:
			require.NoError(t, err)
			require.Empty(t, code.SessionID)
			require.Empty(t, code.FactorID)
			pending, e := s.openPending(j, r)
			require.NoError(t, e)
			expected, e := accountvault.GenerateCode(accountvault.Input{Email: r.Email, Secret: pending.Secret, Algorithm: "SHA1", Digits: 6, Period: 30}, s.now())
			require.NoError(t, e)
			require.Equal(t, expected.Code, code.Code.Code)
		}
		activation, e := s.Code(context.Background(), grant, j.ID, token, j.Revision, true)
		if j.Phase != "activate_intent" {
			require.Error(t, e)
			require.Nil(t, activation)
		} else {
			require.NoError(t, e)
			require.Equal(t, "synthetic-session", activation.SessionID)
			require.Equal(t, "synthetic-new-factor", activation.FactorID)
		}
	}
}
