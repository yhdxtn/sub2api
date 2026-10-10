package routes

import (
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

// registerAccountVaultRoutes must only receive RegisterAdminRoutes' admin group,
// after AdminAuth and the audit middleware. No public/user route mounts the vault.
func registerAccountVaultRoutes(admin *gin.RouterGroup, h *handler.Handlers, stepUp middleware.StepUpAuthMiddleware) {
	if h.Admin.AccountVault == nil {
		return
	}
	vault := admin.Group("/account-vault")
	vault.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, private")
		c.Header("Pragma", "no-cache")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Add("Vary", "Authorization")
		c.Next()
	})
	vault.GET("/status", h.Admin.AccountVault.Status)
	vault.GET("", h.Admin.AccountVault.List)
	vault.GET("/groups", h.Admin.AccountVault.Groups)
	vault.POST("/groups/assign", h.Admin.AccountVault.AssignGroup)
	vault.POST("/import", gin.HandlerFunc(stepUp), h.Admin.AccountVault.Import)
	vault.POST("/parse", h.Admin.AccountVault.Parse)
	vault.POST("/codes", h.Admin.AccountVault.Codes)
	vault.POST("/export-text", gin.HandlerFunc(stepUp), h.Admin.AccountVault.ExportText)
	vault.POST("/:id/password", gin.HandlerFunc(stepUp), h.Admin.AccountVault.Password)
	vault.POST("/:id/secret", gin.HandlerFunc(stepUp), h.Admin.AccountVault.Secret)
	vault.DELETE("/:id", h.Admin.AccountVault.Delete)
	registerAccountVaultRotationRoutes(vault, h, stepUp)
}

func registerAccountVaultRotationRoutes(vault *gin.RouterGroup, h *handler.Handlers, stepUp middleware.StepUpAuthMiddleware) {
	if h.Admin.AccountVaultRotation == nil {
		return
	}
	rotation := vault.Group("/rotation")
	handler := h.Admin.AccountVaultRotation
	vault.GET("/automation/settings", handler.AutomationSettings)
	vault.POST("/automation/settings", gin.HandlerFunc(stepUp), handler.SetAutomation)
	vault.POST("/automation/query", handler.AutomationHealth)
	vault.POST("/automation/refresh", gin.HandlerFunc(stepUp), handler.RefreshAutomationHealth)
	vault.POST("/automation/reauthorize", gin.HandlerFunc(stepUp), handler.ReauthorizeInvalid)
	vault.POST("/session/queue", gin.HandlerFunc(stepUp), handler.QueueSessions)
	vault.POST("/session/jobs/query", handler.QuerySessions)
	vault.POST("/session/export", gin.HandlerFunc(stepUp), handler.ExportSessions)
	rotation.POST("/queue", gin.HandlerFunc(stepUp), handler.Queue)
	rotation.POST("/jobs/query", handler.Query)
	rotation.POST("/:job/resume", gin.HandlerFunc(stepUp), handler.Resume)
	rotation.POST("/:job/cancel", gin.HandlerFunc(stepUp), handler.Cancel)
	rotation.POST("/worker-token", gin.HandlerFunc(stepUp), handler.CreateWorkerToken)
	rotation.DELETE("/worker-token", gin.HandlerFunc(stepUp), handler.RevokeWorkerTokens)
}

// Worker endpoints accept only short-lived rotation capabilities created by an
// administrator. Each handler validates the capability and the administrator's
// current role/status/token version; regular user and admin JWTs are not worker
// capabilities. No token is accepted in the URL or query string.
func RegisterAccountVaultWorkerRoutes(v1 *gin.RouterGroup, h *handler.Handlers) {
	if h.Admin == nil || h.Admin.AccountVaultRotation == nil {
		return
	}
	worker := v1.Group("/account-vault-worker")
	worker.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, private")
		c.Header("Pragma", "no-cache")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Add("Vary", "Authorization")
		c.Next()
	})
	handler := h.Admin.AccountVaultRotation
	worker.POST("/claim", handler.WorkerClaim)
	worker.POST("/:job/heartbeat", handler.WorkerHeartbeat)
	worker.POST("/:job/checkpoint", handler.WorkerCheckpoint)
	worker.POST("/:job/login-code", handler.WorkerLoginCode)
	worker.POST("/:job/activation-code", handler.WorkerActivationCode)
	worker.POST("/:job/pause", handler.WorkerPause)
	worker.POST("/:job/session/save", handler.WorkerSaveSession)
	worker.POST("/:job/session/authorize", handler.WorkerAuthorizeSession)
	worker.POST("/:job/session/complete", handler.WorkerCompleteSession)
}
