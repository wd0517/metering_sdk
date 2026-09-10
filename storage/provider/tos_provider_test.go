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

const (
	testTOSRegion      = "cn-beijing"
	testTOSBucket      = "metering-bucket"
	testTOSRoleTRN     = "trn:iam::1:role/metering"
	testTOSOIDCRoleTRN = "trn:iam::1:role/metering-oidc"
)

// fakeVolcengineSTS replaces the real STS client. A hop left unset fails, so a
// test cannot silently exercise a path it did not expect.
type fakeVolcengineSTS struct {
	oidcFn       func(ctx context.Context, tokenFile, roleTRN string) (*volcengineTOSCredential, error)
	assumeRoleFn func(ctx context.Context, base volcengineTOSCredential, roleTRN string) (*volcengineTOSCredential, error)
}

func (f *fakeVolcengineSTS) assumeRoleWithOIDC(ctx context.Context, tokenFile, roleTRN string) (*volcengineTOSCredential, error) {
	if f.oidcFn == nil {
		return nil, errors.New("unexpected AssumeRoleWithOIDC call")
	}
	return f.oidcFn(ctx, tokenFile, roleTRN)
}

func (f *fakeVolcengineSTS) assumeRole(ctx context.Context, base volcengineTOSCredential, roleTRN string) (*volcengineTOSCredential, error) {
	if f.assumeRoleFn == nil {
		return nil, errors.New("unexpected AssumeRole call")
	}
	return f.assumeRoleFn(ctx, base, roleTRN)
}

func stsCredential(name string, ttl time.Duration) *volcengineTOSCredential {
	return &volcengineTOSCredential{
		accessKey:    name + "-ak",
		secretKey:    name + "-sk",
		sessionToken: name + "-token",
		expiresAt:    time.Now().Add(ttl),
	}
}

func staticTOSCredentialProvider() *staticVolcengineTOSCredentialProvider {
	return &staticVolcengineTOSCredentialProvider{
		credential: volcengineTOSCredential{accessKey: "ak", secretKey: "sk"},
	}
}

// setOIDCEnv points VOLCENGINE_OIDC_* at a token file whose content carries
// surrounding whitespace.
func setOIDCEnv(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("  jwt-token\n"), 0o600))
	t.Setenv(envVolcengineOIDCTokenFile, tokenFile)
	t.Setenv(envVolcengineOIDCRoleTRN, testTOSOIDCRoleTRN)
}

// startOIDCSTSServer serves AssumeRoleWithOIDC with the given handler and
// returns a real STS client pointed at it.
func startOIDCSTSServer(t *testing.T, handler http.HandlerFunc) *volcengineSTS {
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	setOIDCEnv(t)
	return &volcengineSTS{
		region:     testTOSRegion,
		httpClient: srv.Client(),
		oidcURL:    srv.URL + "/?Action=AssumeRoleWithOIDC&Version=2018-01-01",
	}
}

func writeOIDCCredentials(w io.Writer, name string, ttl time.Duration) {
	expiration := time.Now().Add(ttl).Format(time.RFC3339)
	_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":%q,"SecretAccessKey":%q,"SessionToken":%q,"Expiration":%q}}}`,
		name+"-ak", name+"-sk", name+"-token", expiration)
}

func TestBuildTOSEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "regional intranet endpoint", want: "tos-cn-beijing.ivolces.com"},
		{name: "custom host", endpoint: "tos-cn-beijing.volces.com", want: "tos-cn-beijing.volces.com"},
		{name: "custom endpoint keeps its scheme", endpoint: "http://10.0.0.1:8080", want: "http://10.0.0.1:8080"},
		{name: "custom endpoint is trimmed", endpoint: " https://tos.example.com ", want: "https://tos.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, buildTOSEndpoint(testTOSRegion, tt.endpoint))
		})
	}
}

func TestNewTOSProviderRejectsInvalidConfig(t *testing.T) {
	static := &TOSConfig{AccessKey: "ak", SecretAccessKey: "sk"}
	tests := []struct {
		name string
		cfg  *ProviderConfig
		want string
	}{
		{
			name: "wrong type",
			cfg:  &ProviderConfig{Type: ProviderTypeCOS, Bucket: testTOSBucket},
			want: "invalid provider type",
		},
		{
			name: "missing bucket",
			cfg:  &ProviderConfig{Type: ProviderTypeTOS, Region: testTOSRegion, TOS: static},
			want: "bucket name is required",
		},
		{
			// SigV4 needs the region in its signing scope and the TOS SDK cannot
			// infer it from intranet or custom hosts, so an endpoint is no substitute.
			name: "missing region despite endpoint",
			cfg:  &ProviderConfig{Type: ProviderTypeTOS, Bucket: testTOSBucket, Endpoint: "https://tos-cn-beijing.ivolces.com", TOS: static},
			want: "region is required",
		},
		{
			name: "blank region",
			cfg:  &ProviderConfig{Type: ProviderTypeTOS, Bucket: testTOSBucket, Region: "   ", TOS: static},
			want: "region is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTOSProvider(tt.cfg)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestNewTOSProviderStaticCredentials(t *testing.T) {
	provider, err := NewTOSProvider(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: testTOSBucket,
		Region: " " + testTOSRegion + " ",
		TOS:    &TOSConfig{AccessKey: "ak", SecretAccessKey: "sk"},
	})
	require.NoError(t, err)
	require.Equal(t, testTOSBucket, provider.bucket)
}

func TestTOSProviderBuildPath(t *testing.T) {
	provider := &TOSProvider{prefix: "premium/"}
	require.Equal(t, "premium/metering/ru/1.json", provider.buildPath("metering/ru/1.json"))
}

func TestIsTOSNotFound(t *testing.T) {
	require.True(t, isTOSNotFound(&vtos.TosServerError{
		RequestInfo: vtos.RequestInfo{StatusCode: 404},
	}))
	require.False(t, isTOSNotFound(errors.New("upstream returned 404")))
}

func TestVolcengineTOSCredentialProviderStatic(t *testing.T) {
	provider, err := newVolcengineTOSCredentialProvider(&TOSConfig{
		AccessKey:       "ak",
		SecretAccessKey: "sk",
		SessionToken:    "token",
	}, &fakeVolcengineSTS{})
	require.NoError(t, err)

	credential, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, volcengineTOSCredential{accessKey: "ak", secretKey: "sk", sessionToken: "token"}, credential)
}

func TestVolcengineAssumeRoleCachesUntilRefreshWindow(t *testing.T) {
	calls := 0
	sts := &fakeVolcengineSTS{
		assumeRoleFn: func(_ context.Context, base volcengineTOSCredential, roleTRN string) (*volcengineTOSCredential, error) {
			calls++
			require.Equal(t, "ak", base.accessKey)
			require.Equal(t, testTOSRoleTRN, roleTRN)
			return stsCredential("tmp", 2*time.Hour), nil
		},
	}
	provider, err := newVolcengineTOSCredentialProvider(&TOSConfig{
		AccessKey:       "ak",
		SecretAccessKey: "sk",
		AssumeRoleARN:   " " + testTOSRoleTRN + " ",
	}, sts)
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
	// Expiry inside the refresh window (duration/10 = 6 min) but still valid.
	sts := &fakeVolcengineSTS{}
	sts.assumeRoleFn = func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
		return stsCredential("tmp", time.Minute), nil
	}
	provider := newAssumeRoleVolcengineCredentialProvider(staticTOSCredentialProvider(), sts, testTOSRoleTRN)

	first, err := provider.GetCredential(context.Background())
	require.NoError(t, err)

	calls := 0
	sts.assumeRoleFn = func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
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
	// Credential already expired when handed out (clock skew / STS returning
	// a past time): it must never be served, and the refresh error surfaces.
	sts := &fakeVolcengineSTS{}
	sts.assumeRoleFn = func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
		return stsCredential("old", -time.Second), nil
	}
	provider := newAssumeRoleVolcengineCredentialProvider(staticTOSCredentialProvider(), sts, testTOSRoleTRN)

	_, err := provider.GetCredential(context.Background())
	require.ErrorContains(t, err, "expired credential")

	stsErr := errors.New("sts unavailable")
	sts.assumeRoleFn = func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
		return nil, stsErr
	}
	_, err = provider.GetCredential(context.Background())
	require.ErrorIs(t, err, stsErr)
}

func TestVolcengineAssumeRoleHonoursCallerContext(t *testing.T) {
	provider := newAssumeRoleVolcengineCredentialProvider(staticTOSCredentialProvider(), &fakeVolcengineSTS{}, testTOSRoleTRN)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := provider.GetCredential(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestVolcengineOIDCRequiresEnv(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("token"), 0o600))
	tests := []struct {
		name      string
		tokenFile string
		roleTRN   string
		want      string
	}{
		{name: "missing token file variable", roleTRN: testTOSOIDCRoleTRN, want: envVolcengineOIDCTokenFile + " is required"},
		{name: "missing token file", tokenFile: filepath.Join(t.TempDir(), "missing"), roleTRN: testTOSOIDCRoleTRN, want: "stat " + envVolcengineOIDCTokenFile},
		{name: "missing role TRN", tokenFile: tokenFile, want: envVolcengineOIDCRoleTRN + " is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envVolcengineOIDCTokenFile, tt.tokenFile)
			t.Setenv(envVolcengineOIDCRoleTRN, tt.roleTRN)
			_, err := newVolcengineOIDCCredentialProvider(&fakeVolcengineSTS{})
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestVolcengineOIDCTrimsTokenAndUsesRoleMaxDuration(t *testing.T) {
	var gotBody url.Values
	sts := startOIDCSTSServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "AssumeRoleWithOIDC", r.URL.Query().Get("Action"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody, err = url.ParseQuery(string(raw))
		require.NoError(t, err)
		writeOIDCCredentials(w, "oidc", time.Hour)
	})

	provider, err := newVolcengineOIDCCredentialProvider(sts)
	require.NoError(t, err)
	cred, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, "oidc-ak", cred.accessKey)
	require.Equal(t, "oidc-sk", cred.secretKey)
	require.Equal(t, "oidc-token", cred.sessionToken)
	require.WithinDuration(t, time.Now().Add(time.Hour), cred.expiresAt, time.Minute)

	require.Equal(t, "3600", gotBody.Get("DurationSeconds"))
	require.Equal(t, "jwt-token", gotBody.Get("OIDCToken"))
	require.Equal(t, testTOSOIDCRoleTRN, gotBody.Get("RoleTrn"))
	require.Equal(t, defaultTOSAssumeRoleSessionName, gotBody.Get("RoleSessionName"))
}

func TestVolcengineOIDCRejectsOversizedResponseExplicitly(t *testing.T) {
	sts := startOIDCSTSServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Valid JSON that is larger than the cap: the error must name the size
		// limit, not surface as a decode failure on a truncated body.
		padding := strings.Repeat("x", oidcSTSMaxResponseBytes)
		_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":"ak","SecretAccessKey":"sk","SessionToken":%q}}}`, padding)
	})

	provider, err := newVolcengineOIDCCredentialProvider(sts)
	require.NoError(t, err)
	_, err = provider.GetCredential(context.Background())
	require.ErrorContains(t, err, fmt.Sprintf("exceeds %d bytes", oidcSTSMaxResponseBytes))
	require.NotContains(t, err.Error(), "decode OIDC STS response")
}

func TestVolcengineOIDCThenAssumeRoleChain(t *testing.T) {
	setOIDCEnv(t)
	var gotBase volcengineTOSCredential
	sts := &fakeVolcengineSTS{
		oidcFn: func(_ context.Context, tokenFile, roleTRN string) (*volcengineTOSCredential, error) {
			require.Equal(t, os.Getenv(envVolcengineOIDCTokenFile), tokenFile)
			require.Equal(t, testTOSOIDCRoleTRN, roleTRN)
			return stsCredential("oidc", time.Hour), nil
		},
		assumeRoleFn: func(_ context.Context, base volcengineTOSCredential, roleTRN string) (*volcengineTOSCredential, error) {
			gotBase = base
			require.Equal(t, testTOSRoleTRN, roleTRN)
			return stsCredential("wo", time.Hour), nil
		},
	}

	// No static AK: base is the OIDC hop, then AssumeRole into the write role.
	provider, err := newVolcengineTOSCredentialProvider(&TOSConfig{AssumeRoleARN: testTOSRoleTRN}, sts)
	require.NoError(t, err)

	cred, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, "wo-ak", cred.accessKey)
	require.Equal(t, "oidc-ak", gotBase.accessKey)
	require.Equal(t, "oidc-token", gotBase.sessionToken)
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
	stsErr := errors.New("OIDC STS InvalidParameter: DurationSeconds exceed the max session duration")
	calls := 0
	sts := &fakeVolcengineSTS{}
	sts.assumeRoleFn = func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
		calls++
		return nil, stsErr
	}

	// Real provider, real TOS SDK signer and guard; only STS and the network
	// layer are replaced.
	next := &recordingTOSTransport{}
	provider, err := newTOSProvider(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: testTOSBucket,
		Region: testTOSRegion,
		TOS: &TOSConfig{
			AccessKey:       "ak",
			SecretAccessKey: "sk",
			AssumeRoleARN:   testTOSRoleTRN,
		},
	}, sts, next)
	require.NoError(t, err)
	require.Equal(t, 0, calls, "construction must not call STS")

	_, err = provider.Exists(context.Background(), "metering/ru/1.json.gz")
	require.ErrorIs(t, err, stsErr)
	require.ErrorContains(t, err, "resolve TOS credentials")
	require.Equal(t, 0, next.calls, "unsigned request must not reach the network")

	// STS recovers: the same client now signs and the request goes out.
	sts.assumeRoleFn = func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
		return stsCredential("tmp", time.Hour), nil
	}
	_, err = provider.Exists(context.Background(), "metering/ru/1.json.gz")
	require.ErrorContains(t, err, "network reached")
	require.Equal(t, 1, next.calls)
	require.True(t, strings.HasPrefix(next.auth, "TOS4-HMAC-SHA256 Credential=tmp-ak/"), next.auth)
}

func TestVolcengineTOSCredentialsResolvesLazilyAndRecovers(t *testing.T) {
	calls := 0
	stsDown := true
	stsErr := errors.New("DurationSeconds exceed the max session duration")
	sts := &fakeVolcengineSTS{
		assumeRoleFn: func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
			calls++
			if stsDown {
				return nil, stsErr
			}
			return stsCredential("tmp", time.Hour), nil
		},
	}
	provider, err := newVolcengineTOSCredentialProvider(&TOSConfig{
		AccessKey:       "ak",
		SecretAccessKey: "sk",
		AssumeRoleARN:   testTOSRoleTRN,
	}, sts)
	require.NoError(t, err)
	creds := &volcengineTOSCredentials{provider: provider, refreshTimeout: tosCredentialRefreshTimeout}

	// While STS is down: the SDK-facing Credential() degrades to an empty
	// credential instead of panicking or blocking, and the error is recorded.
	require.Equal(t, vtos.Credential{}, creds.Credential())
	require.ErrorIs(t, creds.lastResolveError(), stsErr)
	require.Equal(t, 1, calls)

	// STS recovers on the next request without rebuilding the provider.
	stsDown = false
	got := creds.Credential()
	require.Equal(t, vtos.Credential{
		AccessKeyID:     "tmp-ak",
		AccessKeySecret: "tmp-sk",
		SecurityToken:   "tmp-token",
	}, got)
	require.Equal(t, 2, calls)

	// Cached until the refresh window; no extra STS call.
	require.Equal(t, got, creds.Credential())
	require.Equal(t, 2, calls)
}

func TestVolcengineTOSCredentialsServesCachedCredentialWhileSTSHangs(t *testing.T) {
	// Inside the refresh window (duration/10 = 6 min) with a minute left.
	sts := &fakeVolcengineSTS{}
	sts.assumeRoleFn = func(context.Context, volcengineTOSCredential, string) (*volcengineTOSCredential, error) {
		return stsCredential("tmp", time.Minute), nil
	}
	creds := &volcengineTOSCredentials{
		provider:       newAssumeRoleVolcengineCredentialProvider(staticTOSCredentialProvider(), sts, testTOSRoleTRN),
		refreshTimeout: 200 * time.Millisecond,
	}
	first, err := creds.resolve()
	require.NoError(t, err)

	// STS hangs until the refresh deadline fires. The timeout is the only
	// context on this path, so it must not discard the still-valid credential.
	sts.assumeRoleFn = func(ctx context.Context, _ volcengineTOSCredential, _ string) (*volcengineTOSCredential, error) {
		<-ctx.Done()
		return nil, fmt.Errorf("Volcengine STS AssumeRole: %w", ctx.Err())
	}
	started := time.Now()
	second, err := creds.resolve()
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Less(t, time.Since(started), 5*time.Second)
}

type blockingTransport struct {
	called bool
}

func (b *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	b.called = true
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-time.After(20 * time.Second):
		return nil, errors.New("STS request was not canceled")
	}
}

func TestTOSCredentialsBoundAssumeRoleRefresh(t *testing.T) {
	// Real volcengine STS client over a transport that never answers: the
	// refresh timeout must reach the HTTP layer and surface as DeadlineExceeded.
	transport := &blockingTransport{}
	sts := newVolcengineSTS(testTOSRegion)
	sts.httpClient = &http.Client{Transport: transport}
	creds := &volcengineTOSCredentials{
		provider:       newAssumeRoleVolcengineCredentialProvider(staticTOSCredentialProvider(), sts, testTOSRoleTRN),
		refreshTimeout: 200 * time.Millisecond,
	}

	started := time.Now()
	cred, err := creds.resolve()
	require.True(t, transport.called)
	require.Empty(t, cred.AccessKeyID)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 5*time.Second)
}
