package service

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const openAIDefaultProxyIDEnv = "OPENAI_DEFAULT_PROXY_ID"

// configuredOpenAIDefaultProxyID is used only when no proxy was selected for
// an OpenAI account or OAuth flow. The setting is optional for other installs.
func configuredOpenAIDefaultProxyID() (*int64, error) {
	raw := strings.TrimSpace(os.Getenv(openAIDefaultProxyIDEnv))
	if raw == "" {
		return nil, nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return nil, fmt.Errorf("%s must be a positive integer", openAIDefaultProxyIDEnv)
	}
	return &id, nil
}

func configuredOpenAIDefaultProxy(ctx context.Context, repo ProxyRepository) (*Proxy, error) {
	id, err := configuredOpenAIDefaultProxyID()
	if err != nil || id == nil {
		return nil, err
	}
	if repo == nil {
		return nil, fmt.Errorf("%s requires a proxy repository", openAIDefaultProxyIDEnv)
	}
	proxy, err := repo.GetByID(ctx, *id)
	if err != nil {
		return nil, fmt.Errorf("load %s=%d: %w", openAIDefaultProxyIDEnv, *id, err)
	}
	if proxy == nil || !proxy.IsActive() {
		return nil, fmt.Errorf("%s=%d must refer to an active proxy", openAIDefaultProxyIDEnv, *id)
	}
	return proxy, nil
}
