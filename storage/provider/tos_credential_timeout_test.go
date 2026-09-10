package provider

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type blockingTOSCredentialTransport struct {
	called bool
}

func (transport *blockingTOSCredentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport.called = true
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-time.After(20 * time.Second):
		return nil, errors.New("STS request was not canceled")
	}
}

func TestTOSFederationTokenBoundsAssumeRoleRefresh(t *testing.T) {
	// Keep the real STS client so this checks that cancellation reaches HTTP.
	transport := &blockingTOSCredentialTransport{}
	originalTransport := http.DefaultClient.Transport
	http.DefaultClient.Transport = transport
	t.Cleanup(func() { http.DefaultClient.Transport = originalTransport })

	originalAssumeRole := assumeVolcengineRole
	assumeVolcengineRole = assumeVolcengineRoleWithSTS
	t.Cleanup(func() { assumeVolcengineRole = originalAssumeRole })

	provider := &tosFederationTokenProvider{
		provider: &assumeRoleVolcengineTOSCredentialProvider{
			baseProvider: &staticVolcengineTOSCredentialProvider{
				credential: volcengineTOSCredential{accessKey: "test-ak", secretKey: "test-sk"},
			},
			roleTRN:  "trn:iam::1:role/test-metering",
			region:   "cn-beijing",
			duration: time.Hour,
		},
		duration: time.Hour,
	}

	started := time.Now()
	token, err := provider.FederationToken()
	require.True(t, transport.called)
	require.Nil(t, token)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 15*time.Second)
}
