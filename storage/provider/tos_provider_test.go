package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	vtos "github.com/volcengine/ve-tos-golang-sdk/v2/tos"
)

func TestBuildTOSEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		region   string
		endpoint string
		want     string
	}{
		{
			name:   "builds regional intranet endpoint",
			region: "cn-beijing",
			want:   "tos-cn-beijing.ivolces.com",
		},
		{
			name:     "uses custom endpoint host",
			endpoint: "tos-cn-beijing.ivolces.com",
			want:     "tos-cn-beijing.ivolces.com",
		},
		{
			name:     "strips https scheme",
			endpoint: "https://tos-cn-beijing.ivolces.com",
			want:     "tos-cn-beijing.ivolces.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildTOSEndpoint(tt.region, tt.endpoint)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNewTOSProviderRequiresRegionEvenWithEndpoint(t *testing.T) {
	// SigV4 needs the region in its signing scope and the TOS SDK cannot infer
	// it from intranet or custom hosts, so a custom endpoint is not a substitute.
	for _, region := range []string{"", "   "} {
		_, err := NewTOSProvider(&ProviderConfig{
			Type:     ProviderTypeTOS,
			Bucket:   "nextgen-metering-dev-cn-beijing-ng",
			Region:   region,
			Endpoint: "https://tos-cn-beijing.ivolces.com",
			TOS: &TOSConfig{
				AccessKey:       "ak",
				SecretAccessKey: "sk",
			},
		})
		require.ErrorContains(t, err, "region is required for TOS provider")
	}
}

func TestNewTOSProviderTrimsRegion(t *testing.T) {
	provider, err := NewTOSProvider(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: "nextgen-metering-dev-cn-beijing-ng",
		Region: " cn-beijing ",
		TOS: &TOSConfig{
			AccessKey:       "ak",
			SecretAccessKey: "sk",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, provider)
}

func TestIsTOSNotFound(t *testing.T) {
	require.True(t, isTOSNotFound(&vtos.TosServerError{
		RequestInfo: vtos.RequestInfo{StatusCode: 404},
	}))
	require.False(t, isTOSNotFound(errors.New("upstream returned 404")))
}

func TestNewTOSProviderStaticCredentials(t *testing.T) {
	provider, err := NewTOSProvider(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: "nextgen-metering-dev-cn-beijing-ng",
		Region: "cn-beijing",
		TOS: &TOSConfig{
			AccessKey:       "ak",
			SecretAccessKey: "sk",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, provider)
	require.Equal(t, "nextgen-metering-dev-cn-beijing-ng", provider.bucket)
}

func TestNewTOSProviderRejectsWrongType(t *testing.T) {
	_, err := NewTOSProvider(&ProviderConfig{Type: ProviderTypeCOS, Bucket: "bucket"})
	require.ErrorContains(t, err, "invalid provider type")
}

func TestNewTOSProviderRequiresBucket(t *testing.T) {
	_, err := NewTOSProvider(&ProviderConfig{Type: ProviderTypeTOS, Region: "cn-beijing"})
	require.ErrorContains(t, err, "bucket name is required")
}

func TestVolcengineTOSCredentialsProviderStatic(t *testing.T) {
	provider, err := newVolcengineTOSCredentialProvider(&TOSConfig{
		AccessKey:       "ak",
		SecretAccessKey: "sk",
		SessionToken:    "token",
	}, "cn-beijing")
	require.NoError(t, err)

	credential, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, "ak", credential.accessKey)
	require.Equal(t, "sk", credential.secretKey)
	require.Equal(t, "token", credential.sessionToken)
}

func TestVolcengineAssumeRoleCachesUntilRefreshWindow(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })

	calls := 0
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		calls++
		return &volcengineAssumeRoleResult{
			accessKey:    "tmp-ak",
			secretKey:    "tmp-sk",
			sessionToken: "tmp-token",
			expiresAt:    time.Now().Add(2 * time.Hour),
		}, nil
	}

	provider, err := newVolcengineTOSCredentialProvider(&TOSConfig{
		AccessKey:       "ak",
		SecretAccessKey: "sk",
		AssumeRoleARN:   "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo",
	}, "cn-beijing")
	require.NoError(t, err)

	first, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	second, err := provider.GetCredential(context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, calls)
	require.Equal(t, first, second)
	require.Equal(t, "tmp-ak", first.accessKey)
}

func TestVolcengineAssumeRoleReusesValidCredentialAfterRefreshError(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })

	// Expiry inside the refresh window (duration/10 = 6 min) but still valid.
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return &volcengineAssumeRoleResult{
			accessKey:    "tmp-ak",
			secretKey:    "tmp-sk",
			sessionToken: "tmp-token",
			expiresAt:    time.Now().Add(time.Minute),
		}, nil
	}
	provider := newAssumeRoleVolcengineCredentialProvider(
		&staticVolcengineTOSCredentialProvider{credential: volcengineTOSCredential{accessKey: "ak", secretKey: "sk"}},
		"trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo", "cn-beijing")

	first, err := provider.GetCredential(context.Background())
	require.NoError(t, err)

	calls := 0
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		calls++
		return nil, errors.New("sts unavailable")
	}

	// Inside the window every call retries STS synchronously; while it fails
	// the still-valid credential is served.
	second, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 1, calls)
}

func TestVolcengineAssumeRoleFailsClosedOnceExpired(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })

	// Credential already expired when handed out (clock skew / STS returning
	// a past time): it must never be served, and the refresh error surfaces.
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return &volcengineAssumeRoleResult{
			accessKey:    "old-ak",
			secretKey:    "old-sk",
			sessionToken: "old-token",
			expiresAt:    time.Now().Add(-time.Second),
		}, nil
	}
	provider := newAssumeRoleVolcengineCredentialProvider(
		&staticVolcengineTOSCredentialProvider{credential: volcengineTOSCredential{accessKey: "ak", secretKey: "sk"}},
		"trn:iam::1:role/metering", "cn-beijing")

	_, err := provider.GetCredential(context.Background())
	require.ErrorContains(t, err, "expired credential")

	stsErr := errors.New("sts unavailable")
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return nil, stsErr
	}
	_, err = provider.GetCredential(context.Background())
	require.ErrorIs(t, err, stsErr)
}

func TestVolcengineAssumeRoleHonoursCallerContext(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })

	calls := 0
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		calls++
		return nil, errors.New("must not be called")
	}
	provider := newAssumeRoleVolcengineCredentialProvider(
		&staticVolcengineTOSCredentialProvider{credential: volcengineTOSCredential{accessKey: "ak", secretKey: "sk"}},
		"trn:iam::1:role/metering", "cn-beijing")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := provider.GetCredential(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, calls)
}

func TestVolcengineOIDCRequiresEnv(t *testing.T) {
	t.Setenv(envVolcengineOIDCTokenFile, "")
	t.Setenv(envVolcengineOIDCRoleTRN, "")
	_, err := newVolcengineOIDCCredentialProvider("cn-beijing")
	require.ErrorContains(t, err, envVolcengineOIDCTokenFile)
}

func TestVolcengineOIDCRequiresExistingTokenFile(t *testing.T) {
	t.Setenv(envVolcengineOIDCTokenFile, filepath.Join(t.TempDir(), "missing"))
	t.Setenv(envVolcengineOIDCRoleTRN, "trn:iam::1:role/metering")
	_, err := newVolcengineOIDCCredentialProvider("cn-beijing")
	require.ErrorContains(t, err, "stat")
}

func TestVolcengineOIDCRequiresRoleTRN(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("token"), 0o600))
	t.Setenv(envVolcengineOIDCTokenFile, tokenFile)
	t.Setenv(envVolcengineOIDCRoleTRN, "")
	_, err := newVolcengineOIDCCredentialProvider("cn-beijing")
	require.ErrorContains(t, err, envVolcengineOIDCRoleTRN)
}

func TestVolcengineOIDCRequiresRegion(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("token"), 0o600))
	t.Setenv(envVolcengineOIDCTokenFile, tokenFile)
	t.Setenv(envVolcengineOIDCRoleTRN, "trn:iam::1:role/metering")
	// No environment fallback: an explicit region is the only source.
	t.Setenv("REGION", "cn-beijing")
	_, err := newVolcengineOIDCCredentialProvider("")
	require.ErrorContains(t, err, "region is required")
}

func TestTOSAssumeRoleDurationMatchesRoleMax(t *testing.T) {
	require.Equal(t, 3600*time.Second, tosAssumeRoleDuration)
}

func TestBuildVolcengineSTSEndpoint(t *testing.T) {
	require.Equal(t, "sts.cn-beijing.volcengineapi.com", buildVolcengineSTSEndpoint("cn-beijing"))
}

// startOIDCSTSServer serves AssumeRoleWithOIDC with the given handler, points
// oidcSTSURL at it for the test, and writes a token file into the env.
func startOIDCSTSServer(t *testing.T, handler http.HandlerFunc) {
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	origURL := oidcSTSURL
	t.Cleanup(func() { oidcSTSURL = origURL })
	oidcSTSURL = func(string) string { return srv.URL + "/?Action=AssumeRoleWithOIDC&Version=2018-01-01" }

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("  jwt-token\n"), 0o600))
	t.Setenv(envVolcengineOIDCTokenFile, tokenFile)
	t.Setenv(envVolcengineOIDCRoleTRN, "trn:iam::1:role/dfs")
}

func TestVolcengineOIDCTrimsTokenAndUsesRoleMaxDuration(t *testing.T) {
	var gotBody url.Values
	startOIDCSTSServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "AssumeRoleWithOIDC", r.URL.Query().Get("Action"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody, err = url.ParseQuery(string(raw))
		require.NoError(t, err)
		expiration := time.Now().Add(time.Hour).Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":"ak","SecretAccessKey":"sk","SessionToken":"tok","Expiration":%q}}}`, expiration)
	})

	provider, err := newVolcengineOIDCCredentialProvider("cn-beijing")
	require.NoError(t, err)
	cred, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, "ak", cred.accessKey)
	require.Equal(t, "sk", cred.secretKey)
	require.Equal(t, "tok", cred.sessionToken)
	require.Equal(t, "3600", gotBody.Get("DurationSeconds"))
	require.Equal(t, "jwt-token", gotBody.Get("OIDCToken"))
	require.Equal(t, "trn:iam::1:role/dfs", gotBody.Get("RoleTrn"))
}

func TestVolcengineOIDCCachesUntilRefreshWindow(t *testing.T) {
	hits := 0
	startOIDCSTSServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		expiration := time.Now().Add(time.Hour).Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":"ak","SecretAccessKey":"sk","SessionToken":"tok","Expiration":%q}}}`, expiration)
	})

	provider, err := newVolcengineOIDCCredentialProvider("cn-beijing")
	require.NoError(t, err)
	first, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	second, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 1, hits)
}

func TestVolcengineOIDCThenAssumeRoleChain(t *testing.T) {
	startOIDCSTSServer(t, func(w http.ResponseWriter, r *http.Request) {
		expiration := time.Now().Add(time.Hour).Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":"oidc-ak","SecretAccessKey":"oidc-sk","SessionToken":"oidc-tok","Expiration":%q}}}`, expiration)
	})

	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })
	var gotBase volcengineTOSCredential
	assumeVolcengineRole = func(_ context.Context, base volcengineTOSCredential, roleTRN, _ string, _ time.Duration, region string) (*volcengineAssumeRoleResult, error) {
		gotBase = base
		require.Equal(t, "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo", roleTRN)
		require.Equal(t, "cn-beijing", region)
		return &volcengineAssumeRoleResult{
			accessKey: "wo-ak", secretKey: "wo-sk", sessionToken: "wo-tok",
			expiresAt: time.Now().Add(time.Hour),
		}, nil
	}

	// No static AK: base is the OIDC hop, then AssumeRole into the write-only role.
	provider, err := newVolcengineTOSCredentialProvider(&TOSConfig{
		AssumeRoleARN: "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo",
	}, "cn-beijing")
	require.NoError(t, err)

	cred, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, "wo-ak", cred.accessKey)
	require.Equal(t, "oidc-ak", gotBase.accessKey)
	require.Equal(t, "oidc-tok", gotBase.sessionToken)
}

func TestVolcengineOIDCRejectsOversizedResponseExplicitly(t *testing.T) {
	startOIDCSTSServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Valid JSON that is larger than the cap: the error must name the size
		// limit, not surface as a decode failure on a truncated body.
		padding := strings.Repeat("x", oidcSTSMaxResponseBytes)
		_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":"ak","SecretAccessKey":"sk","SessionToken":%q}}}`, padding)
	})

	provider, err := newVolcengineOIDCCredentialProvider("cn-beijing")
	require.NoError(t, err)
	_, err = provider.GetCredential(context.Background())
	require.ErrorContains(t, err, fmt.Sprintf("exceeds %d bytes", oidcSTSMaxResponseBytes))
	require.NotContains(t, err.Error(), "decode OIDC STS response")
}

func TestVolcengineOIDCAcceptsLargeSessionTokenUnderCap(t *testing.T) {
	// ~8KB token: well above the old 8<<10 total-body cap, under the new one.
	token := strings.Repeat("t", 8<<10)
	startOIDCSTSServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":"ak","SecretAccessKey":"sk","SessionToken":%q}}}`, token)
	})

	provider, err := newVolcengineOIDCCredentialProvider("cn-beijing")
	require.NoError(t, err)
	cred, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, token, cred.sessionToken)
}

type recordingTOSTransport struct {
	calls int
	auth  string
}

func (r *recordingTOSTransport) RoundTrip(_ context.Context, req *vtos.Request) (*vtos.Response, error) {
	r.calls++
	r.auth = req.Header.Get("Authorization")
	return nil, errors.New("network reached")
}

func TestTOSCredentialGuardSurfacesResolveErrorInsteadOfSending(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })
	stsErr := errors.New("OIDC STS InvalidParameter: DurationSeconds exceed the max session duration")
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return nil, stsErr
	}

	// Real provider, real TOS SDK signer and guard; only the network layer is
	// replaced by a recorder.
	next := &recordingTOSTransport{}
	provider, err := newTOSProvider(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: "nextgen-metering-dev-cn-beijing-ng",
		Region: "cn-beijing",
		TOS: &TOSConfig{
			AccessKey:       "ak",
			SecretAccessKey: "sk",
			AssumeRoleARN:   "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo",
		},
	}, next)
	require.NoError(t, err)

	_, err = provider.Exists(context.Background(), "metering/ru/1.json.gz")
	require.ErrorIs(t, err, stsErr)
	require.ErrorContains(t, err, "resolve TOS credentials")
	require.Equal(t, 0, next.calls, "unsigned request must not reach the network")

	// STS recovers: the same client now signs and the request goes out.
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return &volcengineAssumeRoleResult{
			accessKey: "tmp-ak", secretKey: "tmp-sk", sessionToken: "tmp-token",
			expiresAt: time.Now().Add(time.Hour),
		}, nil
	}
	_, err = provider.Exists(context.Background(), "metering/ru/1.json.gz")
	require.ErrorContains(t, err, "network reached")
	require.Equal(t, 1, next.calls)
	require.True(t, strings.HasPrefix(next.auth, "TOS4-HMAC-SHA256 Credential=tmp-ak/"), next.auth)
}

func TestNewTOSProviderDoesNotCallSTSOnConstruction(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })
	calls := 0
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		calls++
		return nil, errors.New("sts unavailable")
	}

	// Construction must succeed and stay offline even when STS is down; the
	// first storage request resolves credentials, matching the COS provider.
	provider, err := NewTOSProvider(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: "nextgen-metering-dev-cn-beijing-ng",
		Region: "cn-beijing",
		TOS: &TOSConfig{
			AccessKey:       "ak",
			SecretAccessKey: "sk",
			AssumeRoleARN:   "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, provider)
	require.Equal(t, 0, calls)
}

func TestVolcengineTOSCredentialsResolvesLazilyAndRecovers(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })
	calls := 0
	stsDown := true
	stsErr := errors.New("DurationSeconds exceed the max session duration")
	assumeVolcengineRole = func(_ context.Context, _ volcengineTOSCredential, roleTRN, sessionName string, duration time.Duration, region string) (*volcengineAssumeRoleResult, error) {
		calls++
		require.Equal(t, "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo", roleTRN)
		require.Equal(t, defaultTOSAssumeRoleSessionName, sessionName)
		require.Equal(t, tosAssumeRoleDuration, duration)
		require.Equal(t, "cn-beijing", region)
		if stsDown {
			return nil, stsErr
		}
		return &volcengineAssumeRoleResult{
			accessKey:    "tmp-ak",
			secretKey:    "tmp-sk",
			sessionToken: "tmp-token",
			expiresAt:    time.Now().Add(time.Hour),
		}, nil
	}

	creds, err := newVolcengineTOSCredentials(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: "nextgen-metering-dev-cn-beijing-ng",
		Region: "cn-beijing",
		TOS: &TOSConfig{
			AccessKey:       "ak",
			SecretAccessKey: "sk",
			AssumeRoleARN:   "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo",
		},
	})
	require.NoError(t, err)
	require.Equal(t, 0, calls)

	// While STS is down: the SDK-facing Credential() degrades to an empty
	// credential instead of panicking or blocking, and the error is recorded.
	_, err = creds.resolve()
	require.ErrorIs(t, err, stsErr)
	require.Equal(t, vtos.Credential{}, creds.Credential())
	require.ErrorIs(t, creds.lastResolveError(), stsErr)
	require.Equal(t, 2, calls)

	// STS recovers on the next request without rebuilding the provider.
	stsDown = false
	got := creds.Credential()
	require.Equal(t, vtos.Credential{
		AccessKeyID:     "tmp-ak",
		AccessKeySecret: "tmp-sk",
		SecurityToken:   "tmp-token",
	}, got)
	require.Equal(t, 3, calls)

	// Cached until the refresh window; no extra STS call.
	require.Equal(t, got, creds.Credential())
	require.Equal(t, 3, calls)
}

func TestTOSProviderBuildPath(t *testing.T) {
	provider := &TOSProvider{prefix: "premium/"}
	require.Equal(t, "premium/metering/ru/1.json", provider.buildPath("metering/ru/1.json"))
}

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

func TestTOSCredentialsBoundAssumeRoleRefresh(t *testing.T) {
	// Keep the real STS client so this checks that cancellation reaches HTTP,
	// but inject the transport through the package-level client rather than
	// http.DefaultClient so no process-wide state is touched.
	transport := &blockingTOSCredentialTransport{}
	originalClient := stsHTTPClient
	stsHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { stsHTTPClient = originalClient })

	originalTimeout := tosCredentialRefreshTimeout
	tosCredentialRefreshTimeout = 200 * time.Millisecond
	t.Cleanup(func() { tosCredentialRefreshTimeout = originalTimeout })

	originalAssumeRole := assumeVolcengineRole
	assumeVolcengineRole = assumeVolcengineRoleWithSTS
	t.Cleanup(func() { assumeVolcengineRole = originalAssumeRole })

	creds := &volcengineTOSCredentials{
		provider: newAssumeRoleVolcengineCredentialProvider(
			&staticVolcengineTOSCredentialProvider{
				credential: volcengineTOSCredential{accessKey: "test-ak", secretKey: "test-sk"},
			},
			"trn:iam::1:role/test-metering",
			"cn-beijing",
		),
	}

	started := time.Now()
	cred, err := creds.resolve()
	require.True(t, transport.called)
	require.Empty(t, cred.AccessKeyID)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 5*time.Second)
}
