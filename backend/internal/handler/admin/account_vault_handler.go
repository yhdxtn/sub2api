package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/accountvault"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// AccountVaultHandler is registered exclusively inside the authenticated admin
// route group. The vault is separate from both gateway accounts and login 2FA.
type AccountVaultHandler struct {
	vault    *service.AccountVaultService
	rotation accountVaultImportRotationQueue
}

type accountVaultImportRotationQueue interface {
	Queue(context.Context, int64, []int64) (*service.AccountVaultRotationQueueResult, error)
}

func NewAccountVaultHandler(vault *service.AccountVaultService) *AccountVaultHandler {
	return &AccountVaultHandler{vault: vault}
}

func ProvideAccountVaultHandler(vault *service.AccountVaultService, rotation *service.AccountVaultRotationService) *AccountVaultHandler {
	return &AccountVaultHandler{vault: vault, rotation: rotation}
}

func (h *AccountVaultHandler) Status(c *gin.Context) {
	response.Success(c, h.vault.Status(c.Request.Context()))
}

func (h *AccountVaultHandler) List(c *gin.Context) {
	page, pageSize := response.ParsePagination(c)
	if pageSize > 100 {
		pageSize = 100
	}
	var group []string
	if names, present := c.Request.URL.Query()["group_name"]; present {
		if len(names) != 1 {
			response.BadRequest(c, "分组筛选参数无效")
			return
		}
		group = []string{names[0]}
	}
	items, total, err := h.vault.List(c.Request.Context(), page, pageSize, c.Query("search"), group...)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Paginated(c, items, total, page, pageSize)
}

func (h *AccountVaultHandler) Groups(c *gin.Context) {
	groups, err := h.vault.Groups(c.Request.Context())
	if !response.ErrorFrom(c, err) {
		response.Success(c, gin.H{"groups": groups})
	}
}

func (h *AccountVaultHandler) AssignGroup(c *gin.Context) {
	var request struct {
		IDs  []int64 `json:"ids"`
		Name *string `json:"group_name"`
	}
	if !bindVaultJSON(c, &request, 8192, "ids", "group_name") {
		return
	}
	if request.Name == nil {
		response.BadRequest(c, "请提供分组名称；空字符串表示未分组")
		return
	}
	if !response.ErrorFrom(c, h.vault.AssignGroup(c.Request.Context(), request.IDs, *request.Name)) {
		response.Success(c, gin.H{"updated": len(request.IDs)})
	}
}

// bindVaultJSON deliberately uses fixed errors: JSON binding errors can contain
// credentials from malformed input and must not reach API responses or audit logs.
func bindVaultJSON(c *gin.Context, target any, limit int64, fields ...string) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
	body, err := io.ReadAll(c.Request.Body)
	defer clear(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			response.Error(c, http.StatusRequestEntityTooLarge, "导入内容超过大小限制")
		} else {
			response.BadRequest(c, "请求格式无效，请检查字段和内容")
		}
		return false
	}
	if !utf8.Valid(body) || !validVaultJSONObject(body, fields) || json.Unmarshal(body, target) != nil {
		response.BadRequest(c, "请求格式无效，请检查字段和内容")
		return false
	}
	return true
}

// encoding/json alone accepts duplicate fields, case aliases and null values.
// Reject those before binding so a credential is never silently replaced by a
// second spelling or occurrence. Input.UnmarshalJSON applies the same rule to
// each structured account; Normalize still reports semantic errors per row.
func validVaultJSONObject(body []byte, fields []string) bool {
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err = decoder.Token()
		field, ok := token.(string)
		if err != nil || !ok || !allowed[field] || seen[field] {
			return false
		}
		seen[field] = true
		var value json.RawMessage
		err = decoder.Decode(&value)
		isNull := bytes.Equal(bytes.TrimSpace(value), []byte("null"))
		clear(value)
		if err != nil || isNull {
			return false
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func (h *AccountVaultHandler) Import(c *gin.Context) {
	var request service.AccountVaultImportRequest
	if !bindVaultJSON(c, &request, 2*service.AccountVaultMaxImportBytes+65536, "content", "items", "dry_run", "rotate_on_import") {
		return
	}
	defer func() { request.Content = ""; request.Items = nil }()
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Unauthorized(c, "需要管理员身份")
		return
	}
	result, err := h.vault.Import(c.Request.Context(), subject.UserID, request)
	if response.ErrorFrom(c, err) {
		return
	}
	if request.RotateOnImport && !request.DryRun && result.Created > 0 {
		ids := make([]int64, 0, result.Created)
		for _, row := range result.Rows {
			if row.Status == "created" && row.ID > 0 {
				ids = append(ids, row.ID)
			}
		}
		if h.rotation == nil {
			result.RotationError = "账号已导入，换绑队列暂不可用；请在账号列表中重新发起首次换绑"
		} else {
			result.Rotation, err = h.rotation.Queue(c.Request.Context(), subject.UserID, ids)
			if err != nil {
				result.RotationError = "账号已导入，换绑排队失败；请在账号列表中重新发起首次换绑"
			}
		}
	}
	response.Success(c, result)
}

func (h *AccountVaultHandler) Parse(c *gin.Context) {
	var request struct {
		URI string `json:"uri"`
	}
	if !bindVaultJSON(c, &request, 65536, "uri") {
		return
	}
	if request.URI == "" || len(request.URI) > 8192 {
		response.BadRequest(c, "二维码内容为空或过长")
		return
	}
	input, err := accountvault.ParseURI(request.URI)
	request.URI = ""
	if err != nil {
		response.BadRequest(c, "二维码不是有效的 TOTP 配置，请检查二维码类型和参数")
		return
	}
	response.Success(c, input)
}

func (h *AccountVaultHandler) Codes(c *gin.Context) {
	var request struct {
		IDs []int64 `json:"ids"`
	}
	if !bindVaultJSON(c, &request, 8192, "ids") {
		return
	}
	result, err := h.vault.Codes(c.Request.Context(), request.IDs)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, result)
}

func (h *AccountVaultHandler) ExportText(c *gin.Context) {
	var request struct {
		IDs []int64 `json:"ids"`
	}
	if !bindVaultJSON(c, &request, 8192, "ids") {
		return
	}
	content, err := h.vault.ExportText(c.Request.Context(), request.IDs)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, gin.H{"content": content, "count": len(request.IDs)})
}

func vaultID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "账号编号无效")
		return 0, false
	}
	return id, true
}

func (h *AccountVaultHandler) Password(c *gin.Context) {
	id, ok := vaultID(c)
	if !ok {
		return
	}
	password, err := h.vault.Password(c.Request.Context(), id)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, gin.H{"password": password})
}

func (h *AccountVaultHandler) Secret(c *gin.Context) {
	id, ok := vaultID(c)
	if !ok {
		return
	}
	secret, err := h.vault.Secret(c.Request.Context(), id)
	if response.ErrorFrom(c, err) {
		return
	}
	response.Success(c, gin.H{"secret": secret})
}

func (h *AccountVaultHandler) Delete(c *gin.Context) {
	id, ok := vaultID(c)
	if !ok {
		return
	}
	if response.ErrorFrom(c, h.vault.Delete(c.Request.Context(), id)) {
		return
	}
	response.Success(c, gin.H{"deleted": true})
}
