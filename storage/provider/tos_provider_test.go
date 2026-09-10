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

func TestBuildTOSEndpointRequiresRegionWithoutEndpoint(t *testing.T) {
	_, err := buildTOSEndpoint("", "")
	require.ErrorContains(t, err, "region is required for TOS provider")
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

	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return &volcengineAssumeRoleResult{
			accessKey:    "tmp-ak",
			secretKey:    "tmp-sk",
			sessionToken: "tmp-token",
			expiresAt:    time.Now().Add(time.Hour),
		}, nil
	}

	provider := &assumeRoleVolcengineTOSCredentialProvider{
		baseProvider: &staticVolcengineTOSCredentialProvider{
			credential: volcengineTOSCredential{accessKey: "ak", secretKey: "sk"},
		},
		roleTRN:  "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo",
		region:   "cn-beijing",
		duration: time.Hour,
	}

	first, err := provider.GetCredential(context.Background())
	require.NoError(t, err)

	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return nil, errors.New("sts unavailable")
	}
	provider.expiresAt = time.Now().Add(time.Minute)

	second, err := provider.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, first, second)
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
	t.Setenv(envVolcengineRegion, "")
	_, err := newVolcengineOIDCCredentialProvider("")
	require.ErrorContains(t, err, "region is required")
}

func TestTOSAssumeRoleDurationMatchesRoleMax(t *testing.T) {
	require.Equal(t, 3600*time.Second, tosAssumeRoleDuration)
}

func TestBuildVolcengineSTSEndpoint(t *testing.T) {
	require.Equal(t, "sts.cn-beijing.volcengineapi.com", buildVolcengineSTSEndpoint("cn-beijing"))
}

func TestVolcengineOIDCTrimsTokenAndUsesRoleMaxDuration(t *testing.T) {
	var gotBody url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "AssumeRoleWithOIDC", r.URL.Query().Get("Action"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody, err = url.ParseQuery(string(raw))
		require.NoError(t, err)
		expiration := time.Now().Add(time.Hour).Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, `{"Result":{"Credentials":{"AccessKeyId":"ak","SecretAccessKey":"sk","SessionToken":"tok","Expiration":%q}}}`, expiration)
	}))
	t.Cleanup(srv.Close)

	origURL := oidcSTSURL
	t.Cleanup(func() { oidcSTSURL = origURL })
	oidcSTSURL = func(string) string { return srv.URL + "/?Action=AssumeRoleWithOIDC&Version=2018-01-01" }

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("  jwt-token\n"), 0o600))
	t.Setenv(envVolcengineOIDCTokenFile, tokenFile)
	t.Setenv(envVolcengineOIDCRoleTRN, "trn:iam::1:role/dfs")

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

func TestNewTOSProviderFailsClosedOnAssumeRoleError(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })
	assumeVolcengineRole = func(context.Context, volcengineTOSCredential, string, string, time.Duration, string) (*volcengineAssumeRoleResult, error) {
		return nil, errors.New("DurationSeconds exceed the max session duration")
	}

	_, err := NewTOSProvider(&ProviderConfig{
		Type:   ProviderTypeTOS,
		Bucket: "nextgen-metering-dev-cn-beijing-ng",
		Region: "cn-beijing",
		TOS: &TOSConfig{
			AccessKey:       "ak",
			SecretAccessKey: "sk",
			AssumeRoleARN:   "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo",
		},
	})
	require.ErrorContains(t, err, "DurationSeconds exceed")
}

func TestNewTOSProviderConstructsWhenAssumeRoleSucceeds(t *testing.T) {
	orig := assumeVolcengineRole
	t.Cleanup(func() { assumeVolcengineRole = orig })
	assumeVolcengineRole = func(_ context.Context, _ volcengineTOSCredential, roleTRN, sessionName string, duration time.Duration, region string) (*volcengineAssumeRoleResult, error) {
		require.Equal(t, "trn:iam::2121942738:role/dev-seed-cn-beijing-ng-metering-wo", roleTRN)
		require.Equal(t, defaultTOSAssumeRoleSessionName, sessionName)
		require.Equal(t, tosAssumeRoleDuration, duration)
		require.Equal(t, "cn-beijing", region)
		return &volcengineAssumeRoleResult{
			accessKey:    "tmp-ak",
			secretKey:    "tmp-sk",
			sessionToken: "tmp-token",
			expiresAt:    time.Now().Add(time.Hour),
		}, nil
	}

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
}

func TestTOSProviderBuildPath(t *testing.T) {
	provider := &TOSProvider{prefix: "premium/"}
	require.Equal(t, "premium/metering/ru/1.json", provider.buildPath("metering/ru/1.json"))
}
