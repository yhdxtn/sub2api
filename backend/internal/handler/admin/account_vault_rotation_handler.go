package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type AccountVaultRotationHandler struct {
	rotation *service.AccountVaultRotationService
	accounts *AccountHandler
}

func NewAccountVaultRotationHandler(rotation *service.AccountVaultRotationService) *AccountVaultRotationHandler {
	return &AccountVaultRotationHandler{rotation: rotation}
}
func ProvideAccountVaultRotationHandler(rotation *service.AccountVaultRotationService, accounts *AccountHandler) *AccountVaultRotationHandler {
	return &AccountVaultRotationHandler{rotation: rotation, accounts: accounts}
}

// Validate every object recursively before decoding: exact field names, one
// occurrence, no nulls, and all required fields (including false MFA booleans).
// Errors deliberately never include submitted bytes or decoder error strings.
func strictRotationJSON(raw []byte, t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	if t.Kind() != reflect.Struct {
		return true
	}
	fields := map[string]reflect.StructField{}
	required := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		parts := strings.Split(f.Tag.Get("json"), ",")
		if parts[0] == "" || parts[0] == "-" {
			continue
		}
		fields[parts[0]] = f
		required[parts[0]] = !strings.Contains(f.Tag.Get("json"), ",omitempty")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		field, ok := fields[key]
		if !ok {
			return false
		}
		seen[key] = true
		var nested json.RawMessage
		if decoder.Decode(&nested) != nil {
			return false
		}
		valid := strictRotationJSON(nested, field.Type)
		clear(nested)
		if !valid {
			return false
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return false
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return false
	}
	for key, required := range required {
		if required && !seen[key] {
			return false
		}
	}
	return true
}
func bindRotationJSON(c *gin.Context, target any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32768)
	body, err := io.ReadAll(c.Request.Body)
	defer clear(body)
	if len(bytes.TrimSpace(body)) == 0 && reflect.TypeOf(target).Elem().NumField() == 0 {
		body = []byte("{}")
	}
	if err != nil || !utf8.Valid(body) || !strictRotationJSON(body, reflect.TypeOf(target)) || json.Unmarshal(body, target) != nil {
		response.ErrorFrom(c, service.ErrVaultRotationInvalid)
		return false
	}
	return true
}
func rotationActor(c *gin.Context) (int64, bool) {
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Unauthorized(c, "需要管理员身份")
		return 0, false
	}
	return subject.UserID, true
}
func (h *AccountVaultRotationHandler) Queue(c *gin.Context) {
	var req struct {
		IDs         []int64 `json:"ids"`
		Concurrency *int    `json:"concurrency,omitempty"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	var result *service.AccountVaultRotationQueueResult
	var err error
	if req.Concurrency != nil {
		result, err = h.rotation.QueueConcurrent(c.Request.Context(), actor, req.IDs, *req.Concurrency)
	} else {
		result, err = h.rotation.Queue(c.Request.Context(), actor, req.IDs)
	}
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) Query(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.Query(c.Request.Context(), actor, req.IDs)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, gin.H{"jobs": result})
}
func (h *AccountVaultRotationHandler) Resume(c *gin.Context) {
	var req struct{}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.Resume(c.Request.Context(), actor, c.Param("job"))
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) Cancel(c *gin.Context) {
	var req struct{}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.Cancel(c.Request.Context(), actor, c.Param("job"))
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) CreateWorkerToken(c *gin.Context) {
	var req struct{}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.CreateWorkerToken(c.Request.Context(), actor)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) RevokeWorkerTokens(c *gin.Context) {
	var req struct{}
	if !bindRotationJSON(c, &req) {
		return
	}
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	if response.ErrorFrom(c, h.rotation.RevokeWorkerTokens(c.Request.Context(), actor)) {
		return
	}
	response.Success(c, gin.H{"revoked": true})
}
func (h *AccountVaultRotationHandler) worker(c *gin.Context) (*service.AccountVaultWorkerGrant, bool) {
	header := c.GetHeader("Authorization")
	if len(header) > 128 || !strings.HasPrefix(header, "Bearer ") {
		response.ErrorFrom(c, service.ErrVaultWorkerUnauthorized)
		return nil, false
	}
	grant, err := h.rotation.AuthenticateWorker(c.Request.Context(), strings.TrimPrefix(header, "Bearer "))
	if response.ErrorFrom(c, err) {
		return nil, false
	}
	return grant, true
}
func (h *AccountVaultRotationHandler) WorkerClaim(c *gin.Context) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req struct {
		WorkerID string `json:"worker_id"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	result, err := h.rotation.Claim(c.Request.Context(), grant, req.WorkerID)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) WorkerHeartbeat(c *gin.Context) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
		Revision   int64  `json:"revision"`
		Progress   string `json:"progress,omitempty"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	result, err := h.rotation.Heartbeat(c.Request.Context(), grant, c.Param("job"), req.LeaseToken, req.Revision, req.Progress)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) WorkerCheckpoint(c *gin.Context) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req service.AccountVaultRotationCheckpoint
	if !bindRotationJSON(c, &req) {
		return
	}
	defer func() { req.Enrollment = nil }()
	result, err := h.rotation.Checkpoint(c.Request.Context(), grant, c.Param("job"), req)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) workerCode(c *gin.Context, activation bool) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
		Revision   int64  `json:"revision"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	result, err := h.rotation.Code(c.Request.Context(), grant, c.Param("job"), req.LeaseToken, req.Revision, activation)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
func (h *AccountVaultRotationHandler) WorkerLoginCode(c *gin.Context)      { h.workerCode(c, false) }
func (h *AccountVaultRotationHandler) WorkerActivationCode(c *gin.Context) { h.workerCode(c, true) }
func (h *AccountVaultRotationHandler) WorkerPause(c *gin.Context) {
	grant, ok := h.worker(c)
	if !ok {
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
		Revision   int64  `json:"revision"`
		ErrorCode  string `json:"error_code"`
	}
	if !bindRotationJSON(c, &req) {
		return
	}
	result, err := h.rotation.Pause(c.Request.Context(), grant, c.Param("job"), req.LeaseToken, req.Revision, req.ErrorCode)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}
