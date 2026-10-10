package admin

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
	"time"
)

func (h *AccountVaultRotationHandler) AutomationSettings(c *gin.Context) {
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	result, err := h.rotation.AutomationSettings(c.Request.Context(), actor)
	if !response.ErrorFrom(c, err) {
		response.Success(c, result)
	}
}
func (h *AccountVaultRotationHandler) SetAutomation(c *gin.Context) {
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !bindVaultJSON(c, &req, 1024, "enabled") {
		return
	}
	result, err := h.rotation.SetAutomation(c.Request.Context(), actor, req.Enabled)
	if !response.ErrorFrom(c, err) {
		response.Success(c, result)
	}
}
func (h *AccountVaultRotationHandler) AutomationHealth(c *gin.Context) { h.automationHealth(c, false) }
func (h *AccountVaultRotationHandler) ReauthorizeInvalid(c *gin.Context) {
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	var req struct{}
	if !bindVaultJSON(c, &req, 1024) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 50*time.Second)
	defer cancel()
	result, err := h.rotation.ReauthorizeInvalid(ctx, actor)
	if !response.ErrorFrom(c, err) {
		response.Success(c, result)
	}
}
func (h *AccountVaultRotationHandler) RefreshAutomationHealth(c *gin.Context) {
	h.automationHealth(c, true)
}
func (h *AccountVaultRotationHandler) automationHealth(c *gin.Context, force bool) {
	actor, ok := rotationActor(c)
	if !ok {
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if !bindVaultJSON(c, &req, 8192, "ids") {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 50*time.Second)
	defer cancel()
	rows, err := h.rotation.AutomationHealth(ctx, actor, req.IDs, force)
	if !response.ErrorFrom(c, err) {
		response.Success(c, gin.H{"rows": rows})
	}
}
