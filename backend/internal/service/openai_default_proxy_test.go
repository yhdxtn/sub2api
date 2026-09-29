package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type openAIDefaultProxyRepoStub struct {
	ProxyRepository
	proxy *Proxy
}

func (s *openAIDefaultProxyRepoStub) GetByID(_ context.Context, id int64) (*Proxy, error) {
	if s.proxy != nil && s.proxy.ID == id {
		return s.proxy, nil
	}
	return nil, nil
}

func TestConfiguredOpenAIDefaultProxyID(t *testing.T) {
	t.Setenv(openAIDefaultProxyIDEnv, "")
	id, err := configuredOpenAIDefaultProxyID()
	require.NoError(t, err)
	require.Nil(t, id)

	t.Setenv(openAIDefaultProxyIDEnv, "7")
	id, err = configuredOpenAIDefaultProxyID()
	require.NoError(t, err)
	require.Equal(t, int64(7), *id)

	t.Setenv(openAIDefaultProxyIDEnv, "not-an-id")
	_, err = configuredOpenAIDefaultProxyID()
	require.ErrorContains(t, err, openAIDefaultProxyIDEnv)
}

func TestOpenAIOAuthService_GenerateAuthURL_UsesConfiguredDefaultProxy(t *testing.T) {
	t.Setenv(openAIDefaultProxyIDEnv, "7")
	proxy := &Proxy{ID: 7, Protocol: "http", Host: "127.0.0.1", Port: 17897, Status: StatusActive}
	svc := NewOpenAIOAuthService(&openAIDefaultProxyRepoStub{proxy: proxy}, &openaiOAuthClientAuthURLStub{})
	defer svc.Stop()

	result, err := svc.GenerateAuthURL(context.Background(), nil, "", PlatformOpenAI)
	require.NoError(t, err)
	session, ok := svc.sessionStore.Get(result.SessionID)
	require.True(t, ok)
	require.Equal(t, proxy.URL(), session.ProxyURL)
}
