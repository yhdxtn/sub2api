//go:build unit

package service

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestBenchmarkPromptAndUsage(t *testing.T) {
	c, rec := newTestContext()
	resp := newJSONResponse(http.StatusOK, "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5.5-observed\",\"usage\":{\"input_tokens\":123,\"output_tokens\":456},\"status\":\"completed\"}}\n\n")
	resp.Header.Set("X-Codex-Primary-Used-Percent", "37")
	resp.Header.Set("Set-Cookie", "secret-cookie")
	upstream := &queuedHTTPUpstream{responses: []*http.Response{resp}}
	svc := &AccountTestService{httpUpstream: upstream}
	err := svc.testOpenAIAccountConnection(c, &Account{ID: 99, Type: AccountTypeOAuth, Platform: PlatformOpenAI, Credentials: map[string]any{"access_token": "test-token"}}, "gpt-5.5", "solve this actual task", "")
	require.NoError(t, err)
	body, err := io.ReadAll(upstream.requests[0].Body)
	require.NoError(t, err)
	require.Equal(t, "solve this actual task", gjson.GetBytes(body, "input.0.content.0.text").String())
	require.Contains(t, rec.Body.String(), `"output_tokens":456`)
	require.Contains(t, rec.Body.String(), `gpt-5.5-observed`)
	require.Contains(t, rec.Body.String(), `x-codex-primary-used-percent`)
	require.NotContains(t, rec.Body.String(), "secret-cookie")
}

func TestBenchmarkIncompleteNeverSucceeds(t *testing.T) {
	c, rec := newTestContext()
	svc := &AccountTestService{}
	err := svc.processOpenAIStream(c, strings.NewReader("data: {\"type\":\"response.incomplete\",\"response\":{\"usage\":{\"output_tokens\":12},\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n"))
	require.Error(t, err)
	require.Contains(t, rec.Body.String(), `"output_tokens":12`)
	require.NotContains(t, rec.Body.String(), `"success":true`)
}

func TestBenchmarkFailureWithoutResponseNeverSucceeds(t *testing.T) {
	c, rec := newTestContext()
	svc := &AccountTestService{}
	err := svc.processOpenAIStream(c, strings.NewReader("data: {\"type\":\"response.failed\"}\n\n"))
	require.Error(t, err)
	require.NotContains(t, rec.Body.String(), `"success":true`)
}
