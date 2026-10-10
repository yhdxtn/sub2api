package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/accountvault"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

type accountVaultMemoryRepo struct {
	mu          sync.Mutex
	rows        map[int64]AccountVaultRecord
	next        int64
	fail        bool
	fingerprint string
}

func (m *accountVaultMemoryRepo) EnsureKey(_ context.Context, fingerprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("synthetic database failure")
	}
	if m.fingerprint == "" {
		m.fingerprint = fingerprint
	}
	if m.fingerprint != fingerprint {
		return ErrAccountVaultKeyMismatch
	}
	return nil
}

func newAccountVaultMemoryRepo() *accountVaultMemoryRepo {
	return &accountVaultMemoryRepo{rows: make(map[int64]AccountVaultRecord), next: 1}
}
func (m *accountVaultMemoryRepo) List(_ context.Context, page, size int, search string) ([]AccountVaultRecord, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, 0, errors.New("synthetic database failure")
	}
	rows := make([]AccountVaultRecord, 0)
	for _, row := range m.rows {
		if search == "" || strings.Contains(row.Email, search) {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })
	total := int64(len(rows))
	start := (page - 1) * size
	if start >= len(rows) {
		return []AccountVaultRecord{}, total, nil
	}
	end := start + size
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], total, nil
}
func (m *accountVaultMemoryRepo) GetByID(_ context.Context, id int64) (*AccountVaultRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("synthetic database failure")
	}
	row, ok := m.rows[id]
	if !ok {
		return nil, ErrAccountVaultNotFound
	}
	return &row, nil
}
func (m *accountVaultMemoryRepo) GetByEmail(_ context.Context, email string) (*AccountVaultRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("synthetic database failure")
	}
	for _, row := range m.rows {
		if row.Email == email {
			return &row, nil
		}
	}
	return nil, ErrAccountVaultNotFound
}
func (m *accountVaultMemoryRepo) GetByIDs(_ context.Context, ids []int64) ([]AccountVaultRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("synthetic database failure")
	}
	rows := make([]AccountVaultRecord, 0, len(ids))
	for _, id := range ids {
		if row, ok := m.rows[id]; ok {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })
	return rows, nil
}
func (m *accountVaultMemoryRepo) Create(_ context.Context, record *AccountVaultRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return false, errors.New("synthetic database failure")
	}
	for _, row := range m.rows {
		if row.Email == record.Email {
			return false, nil
		}
	}
	record.ID = m.next
	m.next++
	record.CreatedAt = time.Unix(1, 0)
	record.UpdatedAt = record.CreatedAt
	m.rows[record.ID] = *record
	return true, nil
}
func (m *accountVaultMemoryRepo) Delete(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("synthetic database failure")
	}
	if _, ok := m.rows[id]; !ok {
		return ErrAccountVaultNotFound
	}
	delete(m.rows, id)
	return nil
}

func accountVaultTestService() (*AccountVaultService, *accountVaultMemoryRepo, *config.Config) {
	repo := newAccountVaultMemoryRepo()
	cfg := &config.Config{AccountVault: config.AccountVaultConfig{EncryptionKey: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))}}
	s := NewAccountVaultService(repo, cfg)
	s.now = func() time.Time { return time.UnixMilli(59500) }
	return s, repo, cfg
}
func accountVaultFixture(email string) accountvault.Input {
	return accountvault.Input{Email: email, Password: " private----test-password ", Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Issuer: "Fixture", Algorithm: "SHA1", Digits: 6, Period: 30}
}

func TestAccountVaultServiceImportPreviewAndEncryptedPersistence(t *testing.T) {
	s, repo, _ := accountVaultTestService()
	ctx := context.Background()
	input := accountVaultFixture("fixture@example.test")
	request := AccountVaultImportRequest{Items: []accountvault.Input{input}, DryRun: true}
	preview, err := s.Import(ctx, 7, request)
	require.NoError(t, err)
	require.Equal(t, "ready", preview.Rows[0].Status)
	require.Empty(t, repo.rows)
	request.DryRun = false
	result, err := s.Import(ctx, 7, request)
	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
	stored := repo.rows[result.Rows[0].ID]
	require.Equal(t, int64(7), stored.CreatedBy)
	require.NotEmpty(t, stored.VaultID)
	encoded, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), input.Password)
	require.NotContains(t, string(encoded), input.Secret)
	password, err := s.Password(ctx, stored.ID)
	require.NoError(t, err)
	require.Equal(t, input.Password, password)
	secret, err := s.Secret(ctx, stored.ID)
	require.NoError(t, err)
	require.Equal(t, input.Secret, secret)
	list, total, err := s.List(ctx, 1, 50, "")
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	public, err := json.Marshal(list)
	require.NoError(t, err)
	require.NotContains(t, string(public), input.Password)
	require.NotContains(t, string(public), input.Secret)
	require.NotContains(t, string(public), stored.EncryptedData)
	for _, key := range []string{"\"password\":", "\"secret\":", "encrypted_data", "vault_id"} {
		require.NotContains(t, string(public), key)
	}
}

func TestAccountVaultServiceMixedRowsAndDuplicatesPreserveOriginal(t *testing.T) {
	s, repo, _ := accountVaultTestService()
	ctx := context.Background()
	first := accountVaultFixture("fixture@example.test")
	result, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{first}})
	require.NoError(t, err)
	id := result.Rows[0].ID
	changed := first
	changed.Password = "different-password"
	changed.Secret = "JBSWY3DPEHPK3PXP"
	bad := accountVaultFixture("invalid")
	valid := accountVaultFixture("another@example.test")
	result, err = s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{changed, bad, valid, valid}})
	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
	require.Equal(t, 2, result.Duplicate)
	require.Equal(t, 1, result.Failed)
	require.Len(t, repo.rows, 2)
	password, err := s.Password(ctx, id)
	require.NoError(t, err)
	require.Equal(t, first.Password, password)
	secret, err := s.Secret(ctx, id)
	require.NoError(t, err)
	require.Equal(t, first.Secret, secret)
}

func TestAccountVaultServiceTextSampleIgnoresOAuthMetadata(t *testing.T) {
	s, _, _ := accountVaultTestService()
	content := "\ufeff卡密 1: fixture@example.test---- keep----spaces ----JBSWY3DPEHPK3PXP\r\n" + `{"name":"fixture@example.test","platform":"openai","credentials":{"access_token":"private-marker-do-not-return"}}` + "\r\nbad credential marker"
	result, err := s.Import(context.Background(), 1, AccountVaultImportRequest{Content: content})
	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
	require.Equal(t, 1, result.Ignored)
	require.Equal(t, 1, result.Failed)
	encoded, _ := json.Marshal(result)
	for _, marker := range []string{"private-marker-do-not-return", "bad credential marker", "JBSWY3DPEHPK3PXP", " keep----spaces "} {
		require.NotContains(t, string(encoded), marker)
	}
	password, err := s.Password(context.Background(), result.Rows[0].ID)
	require.NoError(t, err)
	require.Equal(t, " keep----spaces ", password)
}

func TestAccountVaultServiceCodeOrderUnknownIDAndClock(t *testing.T) {
	s, _, _ := accountVaultTestService()
	ctx := context.Background()
	created, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("a@example.test"), accountVaultFixture("b@example.test")}})
	require.NoError(t, err)
	ids := []int64{created.Rows[0].ID, 999, created.Rows[1].ID}
	codes, err := s.Codes(ctx, ids)
	require.NoError(t, err)
	require.Equal(t, int64(59500), codes.ServerTime)
	require.Len(t, codes.Items, 3)
	for i, id := range ids {
		require.Equal(t, id, codes.Items[i].ID)
	}
	require.Equal(t, "287082", codes.Items[0].Code)
	require.Equal(t, int64(60000), codes.Items[0].ExpiresAt)
	require.Equal(t, 1, codes.Items[0].Remaining)
	require.Empty(t, codes.Items[1].Code)
	require.NotEmpty(t, codes.Items[1].Error)
	_, err = s.Codes(ctx, []int64{1, 1})
	require.True(t, infraerrors.IsBadRequest(err))
	_, err = s.Codes(ctx, make([]int64, 201))
	require.True(t, infraerrors.IsBadRequest(err))
}

func TestAccountVaultServiceHidesUnconfirmedRotationTOTP(t *testing.T) {
	s, repo, _ := accountVaultTestService()
	ctx := context.Background()
	created, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("rotation@example.test")}})
	require.NoError(t, err)
	id := created.Rows[0].ID
	for _, test := range []struct {
		state, phase string
		blocked      bool
	}{
		{"required", "", false},
		{"queued", "login", false},
		{"running", "prepared", false},
		{"cancelled", "login", false},
		{"cancelled", "prepared", false},
		{"cancelled", "disable_intent", true},
		{"running", "disable_intent", true},
		{"paused", "disabled", true},
		{"paused", "enroll_intent", true},
		{"running", "enrolled", true},
		{"paused", "activate_intent", true},
		{"running", "verified", true},
		{"completed", "completed", true}, // no completion timestamp yet
		{"blocked", "previously_completed", true},
		{"unknown", "unknown", true},
	} {
		t.Run(test.state+"_"+test.phase, func(t *testing.T) {
			record := repo.rows[id]
			record.RotationState, record.RotationPhase = test.state, test.phase
			repo.rows[id] = record
			codes, err := s.Codes(ctx, []int64{id})
			require.NoError(t, err)
			secret, err := s.Secret(ctx, id)
			if test.blocked {
				require.Empty(t, codes.Items[0].Code)
				require.NotEmpty(t, codes.Items[0].Error)
				require.Error(t, err)
				require.Empty(t, secret)
			} else {
				require.Equal(t, "287082", codes.Items[0].Code)
				require.NoError(t, err)
			}
			password, err := s.Password(ctx, id)
			require.NoError(t, err)
			require.Equal(t, accountVaultFixture("rotation@example.test").Password, password)
		})
	}
	// A confirmed replacement makes only the new encrypted TOTP visible again.
	record := repo.rows[id]
	input := accountVaultFixture(record.Email)
	input.Secret = "JBSWY3DPEHPK3PXP"
	record.EncryptedData, err = s.cipher.Encrypt(record.VaultID, input)
	require.NoError(t, err)
	completed := time.Now()
	record.RotationState, record.RotationPhase, record.RotationCompletedAt = "completed", "completed", &completed
	repo.rows[id] = record
	secret, err := s.Secret(ctx, id)
	require.NoError(t, err)
	require.Equal(t, input.Secret, secret)
	codes, err := s.Codes(ctx, []int64{id})
	require.NoError(t, err)
	require.NotEmpty(t, codes.Items[0].Code)
	require.NotEqual(t, "287082", codes.Items[0].Code)
}

func TestAccountVaultServiceMissingWrongKeyAndTamperingFailClosed(t *testing.T) {
	s, repo, cfg := accountVaultTestService()
	ctx := context.Background()
	created, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("a@example.test")}})
	require.NoError(t, err)
	id := created.Rows[0].ID
	disabled := NewAccountVaultService(repo, &config.Config{})
	require.False(t, disabled.Status(ctx).Ready)
	_, err = disabled.Password(ctx, id)
	require.ErrorIs(t, err, ErrAccountVaultUnavailable)
	wrongCfg := *cfg
	wrongCfg.AccountVault.EncryptionKey = base64.StdEncoding.EncodeToString([]byte("98765432109876543210987654321098"))
	wrong := NewAccountVaultService(repo, &wrongCfg)
	require.False(t, wrong.Status(ctx).Ready)
	_, err = wrong.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("b@example.test")}})
	require.Error(t, err)
	require.Len(t, repo.rows, 1)
	row := repo.rows[id]
	row.Digits = 8
	repo.rows[id] = row
	_, err = s.Password(ctx, id)
	require.Error(t, err)
	codes, err := s.Codes(ctx, []int64{id})
	require.NoError(t, err)
	require.Empty(t, codes.Items[0].Code)
	require.NotEmpty(t, codes.Items[0].Error)
}

func TestAccountVaultServiceKeyBindingSurvivesEmptyVault(t *testing.T) {
	s, repo, cfg := accountVaultTestService()
	ctx := context.Background()
	created, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("first@example.test")}})
	require.NoError(t, err)
	require.NoError(t, s.Delete(ctx, created.Rows[0].ID))
	require.Empty(t, repo.rows)
	require.NotEmpty(t, repo.fingerprint)
	wrongCfg := *cfg
	wrongCfg.AccountVault.EncryptionKey = base64.StdEncoding.EncodeToString([]byte("98765432109876543210987654321098"))
	wrong := NewAccountVaultService(repo, &wrongCfg)
	_, err = wrong.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("second@example.test")}})
	require.ErrorIs(t, err, ErrAccountVaultKeyMismatch)
	require.Empty(t, repo.rows)
	restarted := NewAccountVaultService(repo, cfg)
	result, err := restarted.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("second@example.test")}})
	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
}

type accountVaultEmptyRaceRepo struct {
	*accountVaultMemoryRepo
	barrier sync.WaitGroup
}

func (r *accountVaultEmptyRaceRepo) List(ctx context.Context, page, size int, search string) ([]AccountVaultRecord, int64, error) {
	rows, total, err := r.accountVaultMemoryRepo.List(ctx, page, size, search)
	// Both new processes observe the empty database before either binds a key.
	r.barrier.Done()
	r.barrier.Wait()
	return rows, total, err
}

func TestAccountVaultServiceConcurrentEmptyVaultAllowsOnlyOneKey(t *testing.T) {
	_, memory, firstCfg := accountVaultTestService()
	repo := &accountVaultEmptyRaceRepo{accountVaultMemoryRepo: memory}
	repo.barrier.Add(2)
	secondCfg := *firstCfg
	secondCfg.AccountVault.EncryptionKey = base64.StdEncoding.EncodeToString([]byte("98765432109876543210987654321098"))
	services := []*AccountVaultService{NewAccountVaultService(repo, firstCfg), NewAccountVaultService(repo, &secondCfg)}
	results := make(chan error, 2)
	for i, s := range services {
		go func(i int, s *AccountVaultService) {
			email := []string{"first@example.test", "second@example.test"}[i]
			_, err := s.Import(context.Background(), 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture(email)}})
			results <- err
		}(i, s)
	}
	passed := 0
	for range services {
		if err := <-results; err == nil {
			passed++
		} else {
			require.ErrorIs(t, err, ErrAccountVaultKeyMismatch)
		}
	}
	require.Equal(t, 1, passed)
	require.Len(t, memory.rows, 1)
}

func TestAccountVaultServiceDeleteEmptyPasswordAndStorageFailure(t *testing.T) {
	s, repo, _ := accountVaultTestService()
	ctx := context.Background()
	input := accountVaultFixture("qr@example.test")
	input.Password = ""
	created, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{input}})
	require.NoError(t, err)
	id := created.Rows[0].ID
	_, err = s.Password(ctx, id)
	require.True(t, infraerrors.IsBadRequest(err))
	require.NoError(t, s.Delete(ctx, id))
	require.ErrorIs(t, s.Delete(ctx, id), ErrAccountVaultNotFound)
	repo.fail = true
	_, _, err = s.List(ctx, 1, 50, "")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "synthetic")
}

func TestAccountVaultServiceLimitsAndImportSlots(t *testing.T) {
	s, repo, _ := accountVaultTestService()
	ctx := context.Background()
	for _, request := range []AccountVaultImportRequest{{}, {Content: "a", Items: []accountvault.Input{accountVaultFixture("a@example.test")}}, {Content: strings.Repeat("x", AccountVaultMaxImportBytes+1)}, {Items: make([]accountvault.Input, 501)}} {
		_, err := s.Import(ctx, 1, request)
		require.True(t, infraerrors.IsBadRequest(err))
		require.Empty(t, repo.rows)
	}
	s.importSlots <- struct{}{}
	s.importSlots <- struct{}{}
	_, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("a@example.test")}})
	require.True(t, infraerrors.IsTooManyRequests(err))
	<-s.importSlots
	<-s.importSlots
	_, err = s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{accountVaultFixture("a@example.test")}})
	require.NoError(t, err)
	require.Empty(t, s.importSlots)
}

func TestAccountVaultExportTextPreservesOrderAndReadsCurrentCredentials(t *testing.T) {
	s, repo, _ := accountVaultTestService()
	ctx := context.Background()
	first, second := accountVaultFixture("first@example.test"), accountVaultFixture("second@example.test")
	first.Note = "备注"
	second.Password = ""
	created, err := s.Import(ctx, 1, AccountVaultImportRequest{Items: []accountvault.Input{first, second}})
	require.NoError(t, err)
	a, b := created.Rows[0].ID, created.Rows[1].ID
	// A confirmed rotation replaces the active encrypted seed; export must read
	// that seed rather than an import preview or an earlier cached value.
	record := repo.rows[a]
	first.Secret = "JBSWY3DPEHPK3PXP"
	record.EncryptedData, err = s.cipher.Encrypt(record.VaultID, first)
	require.NoError(t, err)
	completed := time.Now()
	record.RotationState, record.RotationPhase, record.RotationCompletedAt = "completed", "completed", &completed
	repo.rows[a] = record
	content, err := s.ExportText(ctx, []int64{b, a})
	require.NoError(t, err)
	want := second.Email + "--------" + second.Secret + "\n" + first.Email + "----" + first.Password + "----" + first.Secret + "----备注"
	require.Equal(t, want, content)
	parsed, err := accountvault.ParseContent(content)
	require.NoError(t, err)
	require.Len(t, parsed.Rows, 2)
	require.Empty(t, parsed.Rows[0].Error)
	require.Empty(t, parsed.Rows[1].Error)
	require.Equal(t, first.Note, parsed.Rows[1].Input.Note)
	require.Equal(t, first.Password, parsed.Rows[1].Input.Password)
	for _, ids := range [][]int64{nil, {a, a}, {-1}, make([]int64, 201), {b, 999}} {
		content, err = s.ExportText(ctx, ids)
		require.Error(t, err)
		require.Empty(t, content)
	}
	record.RotationState, record.RotationPhase = "running", "activate_intent"
	repo.rows[a] = record
	content, err = s.ExportText(ctx, []int64{b, a})
	require.Error(t, err)
	require.Empty(t, content, "a failed batch must not return any credentials")
	record.RotationState, record.RotationPhase, record.RotationCompletedAt = "completed", "completed", &completed
	record.EncryptedData = "invalid-ciphertext"
	repo.rows[a] = record
	content, err = s.ExportText(ctx, []int64{b, a})
	require.Error(t, err)
	require.Empty(t, content)
}
