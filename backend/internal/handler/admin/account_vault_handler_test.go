package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/accountvault"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type vaultImportHandlerRepo struct {
	service.AccountVaultRepository
	rows map[string]service.AccountVaultRecord
}

func (r *vaultImportHandlerRepo) EnsureKey(context.Context, string) error { return nil }
func (r *vaultImportHandlerRepo) List(context.Context, int, int, string) ([]service.AccountVaultRecord, int64, error) {
	return nil, 0, nil
}
func (r *vaultImportHandlerRepo) GetByEmail(_ context.Context, email string) (*service.AccountVaultRecord, error) {
	record, ok := r.rows[email]
	if !ok {
		return nil, service.ErrAccountVaultNotFound
	}
	return &record, nil
}
func (r *vaultImportHandlerRepo) Create(_ context.Context, record *service.AccountVaultRecord) (bool, error) {
	if _, exists := r.rows[record.Email]; exists {
		return false, nil
	}
	record.ID = int64(len(r.rows) + 1)
	r.rows[record.Email] = *record
	return true, nil
}

type vaultImportHandlerQueue struct {
	calls   int
	actorID int64
	ids     []int64
	err     error
}

func (q *vaultImportHandlerQueue) Queue(_ context.Context, actorID int64, ids []int64) (*service.AccountVaultRotationQueueResult, error) {
	q.calls++
	q.actorID, q.ids = actorID, append([]int64(nil), ids...)
	if q.err != nil {
		return nil, q.err
	}
	result := &service.AccountVaultRotationQueueResult{Rows: []service.AccountVaultRotationQueueRow{}}
	for _, id := range ids {
		result.Rows = append(result.Rows, service.AccountVaultRotationQueueRow{AccountID: id, Status: "queued"})
	}
	return result, nil
}

func TestAccountVaultImportQueuesOnlyNewAccountsAndPreservesImportOnQueueFailure(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	const password = "synthetic-import-password-canary"
	for _, tc := range []struct {
		name           string
		rotate, dryRun bool
		queueError     bool
	}{
		{"first import", true, false, false},
		{"preview does not queue", true, true, false},
		{"ordinary import", false, false, false},
		{"queue failed after import", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &vaultImportHandlerRepo{rows: map[string]service.AccountVaultRecord{"existing@example.test": {ID: 1, Email: "existing@example.test"}}}
			cfg := &config.Config{AccountVault: config.AccountVaultConfig{EncryptionKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("v", 32)))}}
			vault := service.NewAccountVaultService(repo, cfg)
			queue := &vaultImportHandlerQueue{}
			if tc.queueError {
				queue.err = errors.New("synthetic-private-storage-error")
			}
			handler := &AccountVaultHandler{vault: vault, rotation: queue}
			request := service.AccountVaultImportRequest{RotateOnImport: tc.rotate, DryRun: tc.dryRun, Items: []accountvault.Input{
				{Email: "existing@example.test", Password: password, Secret: secret},
				{Email: "new@example.test", Password: password, Secret: secret},
				{Email: "new@example.test", Password: "synthetic-duplicate-password", Secret: secret},
				{Email: "invalid-email", Password: password, Secret: secret},
			}}
			body, err := json.Marshal(request)
			require.NoError(t, err)
			writer := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(writer)
			c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/account-vault/import", strings.NewReader(string(body)))
			c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 41})
			handler.Import(c)
			require.Equal(t, http.StatusOK, writer.Code)
			var envelope struct {
				Code int                              `json:"code"`
				Data service.AccountVaultImportResult `json:"data"`
			}
			require.NoError(t, json.Unmarshal(writer.Body.Bytes(), &envelope))
			require.Zero(t, envelope.Code)
			require.Equal(t, 2, envelope.Data.Duplicate)
			require.Equal(t, 1, envelope.Data.Failed)
			if tc.dryRun {
				require.Zero(t, envelope.Data.Created)
				require.Len(t, repo.rows, 1)
			} else {
				require.Equal(t, 1, envelope.Data.Created)
				require.Len(t, repo.rows, 2)
				require.NotContains(t, repo.rows["new@example.test"].EncryptedData, password)
			}
			if tc.rotate && !tc.dryRun {
				require.Equal(t, 1, queue.calls)
				require.Equal(t, int64(41), queue.actorID)
				require.Equal(t, []int64{2}, queue.ids)
				require.Equal(t, tc.queueError, envelope.Data.RotationError != "")
				if !tc.queueError {
					require.Equal(t, "queued", envelope.Data.Rotation.Rows[0].Status)
				}
			} else {
				require.Zero(t, queue.calls)
				require.Nil(t, envelope.Data.Rotation)
			}
			for _, canary := range []string{secret, password, "synthetic-private-storage-error", "synthetic-duplicate-password"} {
				require.NotContains(t, writer.Body.String(), canary)
			}
		})
	}
}

func TestAccountVaultJSONRejectsAmbiguousCredentials(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"duplicate content", `{"content":"private-marker","content":"replacement"}`},
		{"case alias", `{"Content":"private-marker"}`},
		{"unknown field", `{"content":"private-marker","owner_id":9}`},
		{"null content", `{"content":null}`},
		{"null items", `{"items":null}`},
		{"null flag", `{"content":"private-marker","dry_run":null}`},
		{"nonboolean flag", `{"content":"private-marker","dry_run":"true"}`},
		{"null object", `null`},
		{"array root", `[]`},
		{"trailing object", `{"content":"private-marker"} {}`},
		{"invalid utf8", "{\"content\":\"private-marker\xff\"}"},
		{"duplicate nested password", `{"items":[{"email":"fixture@example.test","password":"private-marker","password":"replacement"}]}`},
		{"nested alias", `{"items":[{"email":"fixture@example.test","Secret":"private-marker"}]}`},
		{"nested null", `{"items":[{"email":"fixture@example.test","password":null}]}`},
		{"null account", `{"items":[null]}`},
		{"nested wrong type", `{"items":[{"email":"fixture@example.test","password":123}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(writer)
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			var input service.AccountVaultImportRequest
			require.False(t, bindVaultJSON(c, &input, 4096, "content", "items", "dry_run"))
			require.Equal(t, http.StatusBadRequest, writer.Code)
			require.NotContains(t, writer.Body.String(), "private-marker")
			require.NotContains(t, writer.Body.String(), "replacement")
		})
	}
}

func TestAccountVaultJSONPreservesPasswordAndRowValidation(t *testing.T) {
	writer := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(writer)
	c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`{"items":[{"email":"not-an-email","password":"  keep----spaces  ","secret":"JBSWY3DPEHPK3PXP"}],"dry_run":true}`+"\n\t"))
	var input service.AccountVaultImportRequest
	require.True(t, bindVaultJSON(c, &input, 4096, "content", "items", "dry_run"))
	require.True(t, input.DryRun)
	require.Len(t, input.Items, 1)
	require.Equal(t, "  keep----spaces  ", input.Items[0].Password)
	// Structural JSON checks must not turn one invalid email into a failed
	// entire request. Semantic validation belongs to the batch service.
	require.Equal(t, "not-an-email", input.Items[0].Email)
}

func TestAccountVaultJSONEnforcesBoundedBodyAndEndpointFields(t *testing.T) {
	t.Run("bounded body", func(t *testing.T) {
		writer := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(writer)
		c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"content":"`+strings.Repeat("a", 128)+`"}`))
		var input service.AccountVaultImportRequest
		require.False(t, bindVaultJSON(c, &input, 32, "content", "items", "dry_run"))
		require.Equal(t, http.StatusRequestEntityTooLarge, writer.Code)
	})
	for _, body := range []string{`{"ids":[1],"ids":[2]}`, `{"IDs":[1]}`, `{"ids":null}`, `{"ids":[1],"content":"private-marker"}`} {
		t.Run(body, func(t *testing.T) {
			writer := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(writer)
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			var input struct {
				IDs []int64 `json:"ids"`
			}
			require.False(t, bindVaultJSON(c, &input, 4096, "ids"))
			require.Equal(t, http.StatusBadRequest, writer.Code)
		})
	}
}

func TestAccountVaultJSONImportRotationFlag(t *testing.T) {
	for _, test := range []struct {
		body string
		ok   bool
	}{
		{`{"content":"fixture@example.test--------JBSWY3DPEHPK3PXP","rotate_on_import":true}`, true},
		{`{"content":"private-marker","rotate_on_import":null}`, false},
		{`{"content":"private-marker","rotate_on_import":true,"rotate_on_import":false}`, false},
		{`{"content":"private-marker","Rotate_On_Import":true}`, false},
		{`{"content":"private-marker","rotate_on_import":"true"}`, false},
	} {
		writer := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(writer)
		c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
		var input service.AccountVaultImportRequest
		require.Equal(t, test.ok, bindVaultJSON(c, &input, 4096, "content", "items", "dry_run", "rotate_on_import"))
		if test.ok {
			require.True(t, input.RotateOnImport)
		}
		require.NotContains(t, writer.Body.String(), "private-marker")
	}
}
