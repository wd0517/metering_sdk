package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	vtos "github.com/volcengine/ve-tos-golang-sdk/v2/tos"
	volcsts "github.com/volcengine/volcengine-go-sdk/service/sts"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	vecredentials "github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

const (
	defaultTOSAssumeRoleSessionName = "metering-writer"
	// Match live Role MaxSessionDuration and the TiKV Volcengine OIDC client.
	// The official Go OIDC provider sends DurationSeconds+60 and is rejected
	// with InvalidParameter when the Role max is 3600.
	tosAssumeRoleDuration = 3600 * time.Second
	// A successful AssumeRoleWithOIDC response is a few KB (the SessionToken
	// dominates). 64KB leaves ample headroom while still bounding a hostile or
	// misrouted endpoint; exceeding it is reported explicitly instead of
	// surfacing as a JSON decode error on a truncated body.
	oidcSTSMaxResponseBytes    = 64 << 10
	envVolcengineOIDCTokenFile = "VOLCENGINE_OIDC_TOKEN_FILE"
	envVolcengineOIDCRoleTRN   = "VOLCENGINE_OIDC_ROLE_TRN"
)

var (
	assumeVolcengineRole = assumeVolcengineRoleWithSTS
	oidcSTSURL           = volcengineOIDCSTSURL
	// tosCredentialRefreshTimeout bounds one credential refresh, which is at
	// most two STS hops (AssumeRoleWithOIDC, then AssumeRole). The TOS
	// credentials interface has no request context, so this is the only
	// deadline on that path. Package-level so tests can shorten it.
	tosCredentialRefreshTimeout = 10 * time.Second
	// HTTP clients for the two STS hops. Injected explicitly instead of relying
	// on http.DefaultClient so tests can swap transports without mutating
	// process-wide state. Their timeout is a backstop above
	// tosCredentialRefreshTimeout; the context is the deadline that fires.
	oidcHTTPClient = &http.Client{Timeout: 12 * time.Second}
	stsHTTPClient  = &http.Client{Timeout: 12 * time.Second}
)

// TOSProvider Volcengine TOS storage provider implementation.
type TOSProvider struct {
	client *vtos.ClientV2
	bucket string
	prefix string
}

// NewTOSProvider creates a new TOS storage provider.
func NewTOSProvider(providerConfig *ProviderConfig) (*TOSProvider, error) {
	return newTOSProvider(providerConfig, nil)
}

// newTOSProvider builds the provider. next is the network transport placed
// behind the credential guard; nil selects the SDK's tuned default transport
// (dial/read/write timeouts, DNS cache, connection pool). Tests inject a fake.
func newTOSProvider(providerConfig *ProviderConfig, next vtos.Transport) (*TOSProvider, error) {
	if providerConfig.Type != ProviderTypeTOS {
		return nil, fmt.Errorf("invalid provider type: %s, expected: %s", providerConfig.Type, ProviderTypeTOS)
	}
	if providerConfig.Bucket == "" {
		return nil, fmt.Errorf("bucket name is required for TOS provider")
	}
	// TOS signs with SigV4, whose credential scope embeds the region. The TOS
	// SDK can only infer it for a handful of public volces.com hosts, not the
	// intranet or custom endpoints used here, so an empty region would build a
	// client whose every request fails with 403. Fail at construction instead.
	region := strings.TrimSpace(providerConfig.Region)
	if region == "" {
		return nil, fmt.Errorf("region is required for TOS provider (SigV4 signing scope), even when endpoint is set")
	}

	endpoint, err := buildTOSEndpoint(region, providerConfig.Endpoint)
	if err != nil {
		return nil, err
	}

	credentials, err := newVolcengineTOSCredentials(providerConfig)
	if err != nil {
		return nil, err
	}

	if next == nil {
		transportConfig := vtos.DefaultTransportConfig()
		next = vtos.NewDefaultTransport(&transportConfig)
	}
	client, err := vtos.NewClientV2(endpoint,
		vtos.WithRegion(region),
		vtos.WithCredentials(credentials),
		vtos.WithTransport(&tosCredentialGuardTransport{creds: credentials, next: next}),
	)
	if err != nil {
		return nil, fmt.Errorf("create TOS client: %w", err)
	}

	return &TOSProvider{
		client: client,
		bucket: providerConfig.Bucket,
		prefix: providerConfig.Prefix,
	}, nil
}

// buildTOSEndpoint returns the TOS host: an explicit endpoint with any scheme
// stripped, or the regional intranet endpoint. Callers guarantee region is set.
func buildTOSEndpoint(region, endpoint string) (string, error) {
	if value := strings.TrimSpace(endpoint); value != "" {
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
		if value == "" {
			return "", fmt.Errorf("invalid TOS endpoint")
		}
		return value, nil
	}
	return fmt.Sprintf("tos-%s.ivolces.com", strings.TrimSpace(region)), nil
}

func buildVolcengineSTSEndpoint(region string) string {
	return fmt.Sprintf("sts.%s.volcengineapi.com", strings.TrimSpace(region))
}

func volcengineOIDCSTSURL(region string) string {
	return "https://" + buildVolcengineSTSEndpoint(region) + "/?Action=AssumeRoleWithOIDC&Version=2018-01-01"
}

func (p *TOSProvider) buildPath(path string) string {
	if p.prefix == "" {
		return path
	}
	prefix := strings.TrimSuffix(p.prefix, "/")
	path = strings.TrimPrefix(path, "/")
	return prefix + "/" + path
}

// Upload implements ObjectStorageProvider.
func (p *TOSProvider) Upload(ctx context.Context, path string, data io.Reader) error {
	fullPath := p.buildPath(path)
	_, err := p.client.PutObjectV2(ctx, &vtos.PutObjectV2Input{
		PutObjectBasicInput: vtos.PutObjectBasicInput{
			Bucket: p.bucket,
			Key:    fullPath,
		},
		Content: data,
	})
	return err
}

// Download implements ObjectStorageProvider.
func (p *TOSProvider) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath := p.buildPath(path)
	result, err := p.client.GetObjectV2(ctx, &vtos.GetObjectV2Input{
		Bucket: p.bucket,
		Key:    fullPath,
	})
	if err != nil {
		return nil, err
	}
	return result.Content, nil
}

// Delete implements ObjectStorageProvider.
func (p *TOSProvider) Delete(ctx context.Context, path string) error {
	fullPath := p.buildPath(path)
	_, err := p.client.DeleteObjectV2(ctx, &vtos.DeleteObjectV2Input{
		Bucket: p.bucket,
		Key:    fullPath,
	})
	return err
}

// Exists implements ObjectStorageProvider.
func (p *TOSProvider) Exists(ctx context.Context, path string) (bool, error) {
	fullPath := p.buildPath(path)
	_, err := p.client.HeadObjectV2(ctx, &vtos.HeadObjectV2Input{
		Bucket: p.bucket,
		Key:    fullPath,
	})
	if err != nil {
		if isTOSNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// List implements ObjectStorageProvider.
func (p *TOSProvider) List(ctx context.Context, prefix string) ([]string, error) {
	fullPrefix := p.buildPath(prefix)
	var (
		token   string
		objects []string
	)
	for {
		output, err := p.client.ListObjectsV2(ctx, &vtos.ListObjectsV2Input{
			Bucket: p.bucket,
			ListObjectsInput: vtos.ListObjectsInput{
				Prefix: fullPrefix,
				Marker: token,
			},
		})
		if err != nil {
			return nil, err
		}
		for _, object := range output.Contents {
			objects = append(objects, object.Key)
		}
		if !output.IsTruncated {
			break
		}
		token = output.NextMarker
	}
	return objects, nil
}

func isTOSNotFound(err error) bool {
	return vtos.StatusCode(err) == http.StatusNotFound
}

type volcengineTOSCredential struct {
	accessKey    string
	secretKey    string
	sessionToken string
	expiresAt    time.Time
}

type volcengineTOSCredentialProvider interface {
	GetCredential(ctx context.Context) (volcengineTOSCredential, error)
}

type staticVolcengineTOSCredentialProvider struct {
	credential volcengineTOSCredential
}

func (p *staticVolcengineTOSCredentialProvider) GetCredential(ctx context.Context) (volcengineTOSCredential, error) {
	if err := ctx.Err(); err != nil {
		return volcengineTOSCredential{}, err
	}
	return p.credential, nil
}

// cachedVolcengineTOSCredentialProvider caches a short-lived STS credential and
// refreshes it synchronously, mirroring the COS assume-role provider: a refresh
// is attempted once the credential is within duration/10 of expiry; while a
// refresh fails the cached credential is still served until it expires; after
// that the refresh error is returned and an expired credential is never
// handed out. Both the OIDC hop and the AssumeRole hop use this type.
type cachedVolcengineTOSCredentialProvider struct {
	duration time.Duration
	refresh  func(ctx context.Context) (*volcengineTOSCredential, error)

	mu         sync.Mutex
	credential volcengineTOSCredential
}

func (p *cachedVolcengineTOSCredentialProvider) GetCredential(ctx context.Context) (volcengineTOSCredential, error) {
	if err := ctx.Err(); err != nil {
		return volcengineTOSCredential{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	refreshAt := p.credential.expiresAt.Add(-p.duration / 10)
	if p.credential.accessKey != "" && time.Now().Before(refreshAt) {
		return p.credential, nil
	}

	fresh, err := p.refresh(ctx)
	if err != nil {
		return p.credentialAfterRefreshError(ctx, err)
	}
	if fresh.expiresAt.IsZero() || fresh.expiresAt.Unix() <= 0 {
		fresh.expiresAt = time.Now().Add(p.duration)
	}
	p.credential = *fresh
	if !time.Now().Before(p.credential.expiresAt) {
		return volcengineTOSCredential{}, fmt.Errorf("Volcengine credential refresh returned an expired credential")
	}
	return p.credential, nil
}

// credentialAfterRefreshError returns the cached credential while it is still
// valid. Once it has expired, the refresh error must be surfaced.
func (p *cachedVolcengineTOSCredentialProvider) credentialAfterRefreshError(ctx context.Context, refreshErr error) (volcengineTOSCredential, error) {
	if err := ctx.Err(); err != nil {
		return volcengineTOSCredential{}, err
	}
	if p.credential.accessKey != "" && time.Now().Before(p.credential.expiresAt) {
		return p.credential, nil
	}
	return volcengineTOSCredential{}, refreshErr
}

type volcengineAssumeRoleResult struct {
	accessKey    string
	secretKey    string
	sessionToken string
	expiresAt    time.Time
}

// newAssumeRoleVolcengineCredentialProvider chains a base credential (static AK
// or OIDC) into sts:AssumeRole.
func newAssumeRoleVolcengineCredentialProvider(base volcengineTOSCredentialProvider, roleTRN, region string) *cachedVolcengineTOSCredentialProvider {
	return &cachedVolcengineTOSCredentialProvider{
		duration: tosAssumeRoleDuration,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			baseCred, err := base.GetCredential(ctx)
			if err != nil {
				return nil, fmt.Errorf("resolve base credential for AssumeRole: %w", err)
			}
			result, err := assumeVolcengineRole(ctx, baseCred, roleTRN, defaultTOSAssumeRoleSessionName, tosAssumeRoleDuration, region)
			if err != nil {
				return nil, err
			}
			return &volcengineTOSCredential{
				accessKey:    result.accessKey,
				secretKey:    result.secretKey,
				sessionToken: result.sessionToken,
				expiresAt:    result.expiresAt,
			}, nil
		},
	}
}

func newVolcengineTOSCredentialProvider(cfg *TOSConfig, region string) (volcengineTOSCredentialProvider, error) {
	region = strings.TrimSpace(region)

	var baseProvider volcengineTOSCredentialProvider
	if cfg != nil && cfg.AccessKey != "" && cfg.SecretAccessKey != "" {
		baseProvider = &staticVolcengineTOSCredentialProvider{
			credential: volcengineTOSCredential{
				accessKey:    cfg.AccessKey,
				secretKey:    cfg.SecretAccessKey,
				sessionToken: cfg.SessionToken,
			},
		}
	} else {
		oidcProvider, err := newVolcengineOIDCCredentialProvider(region)
		if err != nil {
			return nil, err
		}
		baseProvider = oidcProvider
	}

	if cfg == nil || strings.TrimSpace(cfg.AssumeRoleARN) == "" {
		return baseProvider, nil
	}

	if region == "" {
		return nil, fmt.Errorf("region is required to assume a Volcengine role")
	}

	return newAssumeRoleVolcengineCredentialProvider(baseProvider, strings.TrimSpace(cfg.AssumeRoleARN), region), nil
}

// volcengineTOSCredentials adapts the cached credential provider to the TOS
// SDK Credentials interface. Resolution is lazy: no STS call happens in
// NewTOSProvider; the first storage request triggers it, matching the COS
// provider. This type intentionally does not use vtos.NewFederationCredentials,
// which fetches a token eagerly during construction and, on a failed refresh
// after expiry, keeps signing with the expired credential.
type volcengineTOSCredentials struct {
	provider volcengineTOSCredentialProvider

	mu      sync.Mutex
	lastErr error
}

func (c *volcengineTOSCredentials) resolve() (vtos.Credential, error) {
	// The TOS credentials interface has no request context. Bound the refresh
	// so a stalled STS cannot block storage operations indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), tosCredentialRefreshTimeout)
	defer cancel()
	cred, err := c.provider.GetCredential(ctx)
	if err != nil {
		return vtos.Credential{}, err
	}
	if cred.accessKey == "" || cred.secretKey == "" {
		return vtos.Credential{}, fmt.Errorf("Volcengine TOS credentials are empty")
	}
	return vtos.Credential{
		AccessKeyID:     cred.accessKey,
		AccessKeySecret: cred.secretKey,
		SecurityToken:   cred.sessionToken,
	}, nil
}

// Credential implements vtos.Credentials. The interface cannot return an
// error, so a failed resolve yields an empty Credential and records the error;
// tosCredentialGuardTransport turns the resulting unsigned request into that
// error instead of letting TOS answer 403. Only failures are recorded so the
// most recent cause survives a concurrent successful resolve.
func (c *volcengineTOSCredentials) Credential() vtos.Credential {
	cred, err := c.resolve()
	if err != nil {
		c.mu.Lock()
		c.lastErr = err
		c.mu.Unlock()
		return vtos.Credential{}
	}
	return cred
}

func (c *volcengineTOSCredentials) lastResolveError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// tosSigV4EmptyAccessKeyPrefix is how the TOS SDK renders an Authorization
// header signed with an empty AccessKeyID (Credential=<ak>/<date>/...).
const tosSigV4EmptyAccessKeyPrefix = "TOS4-HMAC-SHA256 Credential=/"

// tosCredentialGuardTransport sits between the TOS SDK signer and the network.
// The SDK signs before RoundTrip, so a request carrying an empty AccessKeyID
// means credential resolution failed; surface that error to the caller (as the
// S3, OSS and COS providers do) instead of sending it and receiving a 403.
type tosCredentialGuardTransport struct {
	creds *volcengineTOSCredentials
	next  vtos.Transport
}

func (t *tosCredentialGuardTransport) RoundTrip(ctx context.Context, req *vtos.Request) (*vtos.Response, error) {
	if strings.HasPrefix(req.Header.Get("Authorization"), tosSigV4EmptyAccessKeyPrefix) {
		err := t.creds.lastResolveError()
		if err == nil {
			err = errors.New("credentials unresolved")
		}
		return nil, fmt.Errorf("resolve TOS credentials: %w", err)
	}
	return t.next.RoundTrip(ctx, req)
}

func newVolcengineTOSCredentials(providerConfig *ProviderConfig) (*volcengineTOSCredentials, error) {
	cfg := (*TOSConfig)(nil)
	if providerConfig != nil {
		cfg = providerConfig.TOS
	}
	region := ""
	if providerConfig != nil {
		region = providerConfig.Region
	}
	provider, err := newVolcengineTOSCredentialProvider(cfg, region)
	if err != nil {
		return nil, err
	}
	return &volcengineTOSCredentials{provider: provider}, nil
}

func newVolcengineOIDCCredentialProvider(region string) (*cachedVolcengineTOSCredentialProvider, error) {
	tokenFile := strings.TrimSpace(os.Getenv(envVolcengineOIDCTokenFile))
	if tokenFile == "" {
		return nil, fmt.Errorf("%s is required", envVolcengineOIDCTokenFile)
	}
	if _, err := os.Stat(tokenFile); err != nil {
		return nil, fmt.Errorf("stat %s: %w", envVolcengineOIDCTokenFile, err)
	}
	roleTRN := strings.TrimSpace(os.Getenv(envVolcengineOIDCRoleTRN))
	if roleTRN == "" {
		return nil, fmt.Errorf("%s is required", envVolcengineOIDCRoleTRN)
	}
	region = strings.TrimSpace(region)
	if region == "" {
		return nil, fmt.Errorf("region is required for Volcengine OIDC")
	}
	return &cachedVolcengineTOSCredentialProvider{
		duration: tosAssumeRoleDuration,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			return assumeVolcengineRoleWithOIDC(ctx, tokenFile, roleTRN, region, tosAssumeRoleDuration)
		},
	}, nil
}

func assumeVolcengineRoleWithOIDC(ctx context.Context, tokenFile, roleTRN, region string, duration time.Duration) (*volcengineTOSCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", envVolcengineOIDCTokenFile, err)
	}
	oidcToken := strings.TrimSpace(string(raw))
	if oidcToken == "" {
		return nil, fmt.Errorf("%s is empty", envVolcengineOIDCTokenFile)
	}
	if duration <= 0 {
		duration = tosAssumeRoleDuration
	}

	form := url.Values{}
	form.Set("RoleTrn", roleTRN)
	form.Set("OIDCToken", oidcToken)
	form.Set("RoleSessionName", defaultTOSAssumeRoleSessionName)
	form.Set("DurationSeconds", fmt.Sprintf("%d", int(duration/time.Second)))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcSTSURL(region), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build OIDC STS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request OIDC STS: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcSTSMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OIDC STS response: status=%d: %w", resp.StatusCode, err)
	}
	if len(body) > oidcSTSMaxResponseBytes {
		return nil, fmt.Errorf("OIDC STS response exceeds %d bytes: status=%d", oidcSTSMaxResponseBytes, resp.StatusCode)
	}

	var stsResp vecredentials.AssumeRoleWithOIDCResponse
	if err := json.Unmarshal(body, &stsResp); err != nil {
		return nil, fmt.Errorf("decode OIDC STS response: status=%d: %w", resp.StatusCode, err)
	}
	if stsResp.ResponseMetadata.Error != nil {
		return nil, fmt.Errorf("OIDC STS %s: %s", stsResp.ResponseMetadata.Error.Code, stsResp.ResponseMetadata.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC STS returned status %d", resp.StatusCode)
	}

	accessKey := strings.TrimSpace(stsResp.Result.Credentials.AccessKeyId)
	secretKey := strings.TrimSpace(stsResp.Result.Credentials.SecretAccessKey)
	token := strings.TrimSpace(stsResp.Result.Credentials.SessionToken)
	if accessKey == "" || secretKey == "" || token == "" {
		return nil, fmt.Errorf("OIDC STS returned empty credentials")
	}

	expiresAt := time.Now().Add(duration)
	if raw := strings.TrimSpace(stsResp.Result.Credentials.Expiration); raw != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, raw); parseErr == nil {
			expiresAt = parsed
		}
	}
	return &volcengineTOSCredential{
		accessKey:    accessKey,
		secretKey:    secretKey,
		sessionToken: token,
		expiresAt:    expiresAt,
	}, nil
}

func assumeVolcengineRoleWithSTS(
	ctx context.Context,
	baseCred volcengineTOSCredential,
	roleTRN, roleSessionName string,
	duration time.Duration,
	region string,
) (*volcengineAssumeRoleResult, error) {
	region = strings.TrimSpace(region)
	if region == "" {
		return nil, fmt.Errorf("region is required to assume a Volcengine role")
	}

	sess, err := session.NewSession(volcengine.NewConfig().
		WithRegion(region).
		WithEndpoint(buildVolcengineSTSEndpoint(region)).
		WithHTTPClient(stsHTTPClient).
		WithCredentials(vecredentials.NewStaticCredentials(baseCred.accessKey, baseCred.secretKey, baseCred.sessionToken)))
	if err != nil {
		return nil, fmt.Errorf("create volcengine session: %w", err)
	}

	output, err := volcsts.New(sess).AssumeRoleWithContext(ctx, &volcsts.AssumeRoleInput{
		RoleTrn:         volcengine.String(roleTRN),
		RoleSessionName: volcengine.String(roleSessionName),
		DurationSeconds: volcengine.Int32(int32(duration / time.Second)),
	})
	if err != nil {
		// The volcengine SDK wraps a canceled context in its own error type
		// without Unwrap. Re-attach the context error so callers can
		// errors.Is(err, context.DeadlineExceeded) and tell a timeout from an
		// STS rejection.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("Volcengine STS AssumeRole: %w (%v)", ctxErr, err)
		}
		return nil, err
	}
	if output == nil || output.Credentials == nil {
		return nil, fmt.Errorf("Volcengine STS returned empty credentials")
	}

	accessKey := volcengine.StringValue(output.Credentials.AccessKeyId)
	secretKey := volcengine.StringValue(output.Credentials.SecretAccessKey)
	token := volcengine.StringValue(output.Credentials.SessionToken)
	if accessKey == "" || secretKey == "" || token == "" {
		return nil, fmt.Errorf("Volcengine STS returned empty credentials")
	}

	expiresAt := time.Now().Add(duration)
	if raw := strings.TrimSpace(volcengine.StringValue(output.Credentials.ExpiredTime)); raw != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, raw); parseErr == nil {
			expiresAt = parsed
		}
	}

	return &volcengineAssumeRoleResult{
		accessKey:    accessKey,
		secretKey:    secretKey,
		sessionToken: token,
		expiresAt:    expiresAt,
	}, nil
}
