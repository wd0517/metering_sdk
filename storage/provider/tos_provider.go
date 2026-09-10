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
	"strconv"
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
	// Volcengine IAM roles default to MaxSessionDuration=3600s and STS rejects
	// a larger DurationSeconds with InvalidParameter, so request exactly that.
	tosAssumeRoleDuration = 3600 * time.Second
	// tosCredentialRefreshTimeout bounds one credential refresh, which is at
	// most two STS hops (AssumeRoleWithOIDC, then AssumeRole). The TOS
	// credentials interface has no request context, so this is the only
	// deadline on that path.
	tosCredentialRefreshTimeout = 10 * time.Second
	// A successful AssumeRoleWithOIDC response is a few KB (the SessionToken
	// dominates). 64KB leaves ample headroom while still bounding a hostile or
	// misrouted endpoint; exceeding it is reported explicitly instead of
	// surfacing as a JSON decode error on a truncated body.
	oidcSTSMaxResponseBytes    = 64 << 10
	envVolcengineOIDCTokenFile = "VOLCENGINE_OIDC_TOKEN_FILE"
	envVolcengineOIDCRoleTRN   = "VOLCENGINE_OIDC_ROLE_TRN"
)

// TOSProvider Volcengine TOS storage provider implementation.
type TOSProvider struct {
	client *vtos.ClientV2
	bucket string
	prefix string
}

// NewTOSProvider creates a new TOS storage provider.
func NewTOSProvider(providerConfig *ProviderConfig) (*TOSProvider, error) {
	return newTOSProvider(providerConfig, nil, nil)
}

// newTOSProvider builds the provider. sts is the STS client behind the
// credential chain and next is the network transport behind the credential
// guard; nil selects the real STS client and the SDK's tuned default
// transport (dial/read/write timeouts, DNS cache, connection pool). Tests
// inject fakes.
func newTOSProvider(providerConfig *ProviderConfig, sts volcengineSTSClient, next vtos.Transport) (*TOSProvider, error) {
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

	if sts == nil {
		sts = newVolcengineSTS(region)
	}
	credentialProvider, err := newVolcengineTOSCredentialProvider(providerConfig.TOS, sts)
	if err != nil {
		return nil, err
	}
	credentials := &volcengineTOSCredentials{
		provider:       credentialProvider,
		refreshTimeout: tosCredentialRefreshTimeout,
	}

	if next == nil {
		transportConfig := vtos.DefaultTransportConfig()
		next = vtos.NewDefaultTransport(&transportConfig)
	}
	client, err := vtos.NewClientV2(buildTOSEndpoint(region, providerConfig.Endpoint),
		vtos.WithRegion(region),
		vtos.WithCredentials(credentials),
		// WithTransport is deprecated in favour of WithHTTPTransport, but it is
		// the only hook that sees the signed *vtos.Request while keeping the
		// SDK's default transport underneath; WithHTTPTransport discards that
		// transport's tuning.
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

// buildTOSEndpoint returns the explicit endpoint or the regional intranet
// endpoint. The TOS SDK parses an optional http:// or https:// scheme itself.
func buildTOSEndpoint(region, endpoint string) string {
	if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
		return endpoint
	}
	return "tos-" + region + ".ivolces.com"
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
	_, err := p.client.PutObjectV2(ctx, &vtos.PutObjectV2Input{
		PutObjectBasicInput: vtos.PutObjectBasicInput{
			Bucket: p.bucket,
			Key:    p.buildPath(path),
		},
		Content: data,
	})
	return err
}

// Download implements ObjectStorageProvider.
func (p *TOSProvider) Download(ctx context.Context, path string) (io.ReadCloser, error) {
	result, err := p.client.GetObjectV2(ctx, &vtos.GetObjectV2Input{
		Bucket: p.bucket,
		Key:    p.buildPath(path),
	})
	if err != nil {
		return nil, err
	}
	return result.Content, nil
}

// Delete implements ObjectStorageProvider.
func (p *TOSProvider) Delete(ctx context.Context, path string) error {
	_, err := p.client.DeleteObjectV2(ctx, &vtos.DeleteObjectV2Input{
		Bucket: p.bucket,
		Key:    p.buildPath(path),
	})
	return err
}

// Exists implements ObjectStorageProvider.
func (p *TOSProvider) Exists(ctx context.Context, path string) (bool, error) {
	_, err := p.client.HeadObjectV2(ctx, &vtos.HeadObjectV2Input{
		Bucket: p.bucket,
		Key:    p.buildPath(path),
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
	input := &vtos.ListObjectsType2Input{
		Bucket:       p.bucket,
		Prefix:       p.buildPath(prefix),
		ListOnlyOnce: true,
	}
	var objects []string
	for {
		output, err := p.client.ListObjectsType2(ctx, input)
		if err != nil {
			return nil, err
		}
		for _, object := range output.Contents {
			objects = append(objects, object.Key)
		}
		if !output.IsTruncated {
			return objects, nil
		}
		input.ContinuationToken = output.NextContinuationToken
	}
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
// refresh fails (or returns an already-expired credential) the cached
// credential is still served until it expires; after that the refresh error is
// returned and an expired credential is never handed out. Both the OIDC hop
// and the AssumeRole hop use this type.
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
	if !time.Now().Before(fresh.expiresAt) {
		return p.credentialAfterRefreshError(ctx, errors.New("Volcengine STS returned an expired credential"))
	}
	p.credential = *fresh
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

func newVolcengineTOSCredentialProvider(cfg *TOSConfig, sts volcengineSTSClient) (volcengineTOSCredentialProvider, error) {
	var base volcengineTOSCredentialProvider
	if cfg != nil && cfg.AccessKey != "" && cfg.SecretAccessKey != "" {
		base = &staticVolcengineTOSCredentialProvider{
			credential: volcengineTOSCredential{
				accessKey:    cfg.AccessKey,
				secretKey:    cfg.SecretAccessKey,
				sessionToken: cfg.SessionToken,
			},
		}
	} else {
		oidc, err := newVolcengineOIDCCredentialProvider(sts)
		if err != nil {
			return nil, err
		}
		base = oidc
	}

	roleTRN := ""
	if cfg != nil {
		roleTRN = strings.TrimSpace(cfg.AssumeRoleARN)
	}
	if roleTRN == "" {
		return base, nil
	}
	return newAssumeRoleVolcengineCredentialProvider(base, sts, roleTRN), nil
}

// newAssumeRoleVolcengineCredentialProvider chains a base credential (static AK
// or OIDC) into sts:AssumeRole.
func newAssumeRoleVolcengineCredentialProvider(base volcengineTOSCredentialProvider, sts volcengineSTSClient, roleTRN string) *cachedVolcengineTOSCredentialProvider {
	return &cachedVolcengineTOSCredentialProvider{
		duration: tosAssumeRoleDuration,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			baseCred, err := base.GetCredential(ctx)
			if err != nil {
				return nil, fmt.Errorf("resolve base credential for AssumeRole: %w", err)
			}
			return sts.assumeRole(ctx, baseCred, roleTRN)
		},
	}
}

// newVolcengineOIDCCredentialProvider reads the token file and role TRN from
// the same environment variables the Volcengine SDK's own OIDC provider uses.
func newVolcengineOIDCCredentialProvider(sts volcengineSTSClient) (*cachedVolcengineTOSCredentialProvider, error) {
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
	return &cachedVolcengineTOSCredentialProvider{
		duration: tosAssumeRoleDuration,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			return sts.assumeRoleWithOIDC(ctx, tokenFile, roleTRN)
		},
	}, nil
}

// volcengineTOSCredentials adapts the cached credential provider to the TOS
// SDK Credentials interface. Resolution is lazy: no STS call happens in
// NewTOSProvider; the first storage request triggers it, matching the COS
// provider. This type intentionally does not use vtos.NewFederationCredentials,
// which fetches a token eagerly during construction and, on a failed refresh
// after expiry, keeps signing with the expired credential.
type volcengineTOSCredentials struct {
	provider       volcengineTOSCredentialProvider
	refreshTimeout time.Duration

	mu      sync.Mutex
	lastErr error
}

func (c *volcengineTOSCredentials) resolve() (vtos.Credential, error) {
	// The TOS credentials interface has no request context. Bound the refresh
	// so a stalled STS cannot block storage operations indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), c.refreshTimeout)
	defer cancel()
	cred, err := c.provider.GetCredential(ctx)
	if err != nil {
		return vtos.Credential{}, err
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

// volcengineSTSClient issues the STS calls behind the TOS credential chain.
type volcengineSTSClient interface {
	assumeRoleWithOIDC(ctx context.Context, tokenFile, roleTRN string) (*volcengineTOSCredential, error)
	assumeRole(ctx context.Context, base volcengineTOSCredential, roleTRN string) (*volcengineTOSCredential, error)
}

// volcengineSTS is the STS client for one region. Each instance owns its
// http.Client: the volcengine SDK mutates the client it is handed (installs a
// Transport and rewrites its Proxy on every call), so sharing one across
// providers or with http.DefaultClient would race.
type volcengineSTS struct {
	region     string
	httpClient *http.Client
	oidcURL    string
}

func newVolcengineSTS(region string) *volcengineSTS {
	return &volcengineSTS{
		region: region,
		// Backstop above tosCredentialRefreshTimeout; the context deadline is
		// the one that normally fires.
		httpClient: &http.Client{Timeout: 12 * time.Second},
		oidcURL:    "https://" + volcengineSTSHost(region) + "/?Action=AssumeRoleWithOIDC&Version=2018-01-01",
	}
}

func volcengineSTSHost(region string) string {
	return "sts." + region + ".volcengineapi.com"
}

// volcengineExpiry parses the RFC3339 expiration STS returns, falling back to
// the requested duration when it is missing or malformed.
func volcengineExpiry(raw string) time.Time {
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw)); err == nil {
		return parsed
	}
	return time.Now().Add(tosAssumeRoleDuration)
}

// assumeRoleWithOIDC calls AssumeRoleWithOIDC directly instead of through the
// SDK's OIDCCredentialsProvider, which sends DurationSeconds+60 and is
// therefore rejected by a role whose MaxSessionDuration is the 3600s default.
func (s *volcengineSTS) assumeRoleWithOIDC(ctx context.Context, tokenFile, roleTRN string) (*volcengineTOSCredential, error) {
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", envVolcengineOIDCTokenFile, err)
	}
	oidcToken := strings.TrimSpace(string(raw))
	if oidcToken == "" {
		return nil, fmt.Errorf("%s is empty", envVolcengineOIDCTokenFile)
	}

	form := url.Values{}
	form.Set("RoleTrn", roleTRN)
	form.Set("OIDCToken", oidcToken)
	form.Set("RoleSessionName", defaultTOSAssumeRoleSessionName)
	form.Set("DurationSeconds", strconv.Itoa(int(tosAssumeRoleDuration/time.Second)))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.oidcURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build OIDC STS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
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

	creds := stsResp.Result.Credentials
	cred := &volcengineTOSCredential{
		accessKey:    strings.TrimSpace(creds.AccessKeyId),
		secretKey:    strings.TrimSpace(creds.SecretAccessKey),
		sessionToken: strings.TrimSpace(creds.SessionToken),
		expiresAt:    volcengineExpiry(creds.Expiration),
	}
	if cred.accessKey == "" || cred.secretKey == "" || cred.sessionToken == "" {
		return nil, errors.New("OIDC STS returned empty credentials")
	}
	return cred, nil
}

func (s *volcengineSTS) assumeRole(ctx context.Context, base volcengineTOSCredential, roleTRN string) (*volcengineTOSCredential, error) {
	sess, err := session.NewSession(volcengine.NewConfig().
		WithRegion(s.region).
		WithEndpoint(volcengineSTSHost(s.region)).
		WithHTTPClient(s.httpClient).
		WithCredentials(vecredentials.NewStaticCredentials(base.accessKey, base.secretKey, base.sessionToken)))
	if err != nil {
		return nil, fmt.Errorf("create volcengine session: %w", err)
	}

	output, err := volcsts.New(sess).AssumeRoleWithContext(ctx, &volcsts.AssumeRoleInput{
		RoleTrn:         volcengine.String(roleTRN),
		RoleSessionName: volcengine.String(defaultTOSAssumeRoleSessionName),
		DurationSeconds: volcengine.Int32(int32(tosAssumeRoleDuration / time.Second)),
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
		return nil, errors.New("Volcengine STS returned empty credentials")
	}

	cred := &volcengineTOSCredential{
		accessKey:    volcengine.StringValue(output.Credentials.AccessKeyId),
		secretKey:    volcengine.StringValue(output.Credentials.SecretAccessKey),
		sessionToken: volcengine.StringValue(output.Credentials.SessionToken),
		expiresAt:    volcengineExpiry(volcengine.StringValue(output.Credentials.ExpiredTime)),
	}
	if cred.accessKey == "" || cred.secretKey == "" || cred.sessionToken == "" {
		return nil, errors.New("Volcengine STS returned empty credentials")
	}
	return cred, nil
}
