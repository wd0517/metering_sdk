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
	// Volcengine role MaxSessionDuration defaults to 3600s; STS rejects more with InvalidParameter.
	tosAssumeRoleDuration = 3600 * time.Second
	// Bounds one refresh (up to two STS hops). vtos.Credentials has no request
	// context, so this is the only deadline on the credential path.
	tosCredentialRefreshTimeout = 10 * time.Second
	// Real responses are a few KB; this bounds a hostile or misrouted endpoint.
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

// newTOSProvider is NewTOSProvider with an injectable STS client and network
// transport; nil selects the real ones.
func newTOSProvider(providerConfig *ProviderConfig, sts volcengineSTSClient, next vtos.Transport) (*TOSProvider, error) {
	if providerConfig.Type != ProviderTypeTOS {
		return nil, fmt.Errorf("invalid provider type: %s, expected: %s", providerConfig.Type, ProviderTypeTOS)
	}
	if providerConfig.Bucket == "" {
		return nil, fmt.Errorf("bucket name is required for TOS provider")
	}
	// The SDK infers the SigV4 region only for public volces.com hosts, never
	// for intranet or custom endpoints; without it every request gets a 403.
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
		// Deprecated, but the only hook that sees the signed request while
		// keeping the SDK's default transport; WithHTTPTransport drops the latter.
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

// buildTOSEndpoint keeps any scheme on a custom endpoint; the SDK parses it.
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

// cachedVolcengineTOSCredentialProvider refreshes synchronously once the
// credential is within duration/10 of expiry. While a refresh fails the cached
// credential is served until it expires; after that the refresh error surfaces.
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
		return p.credentialAfterRefreshError(err)
	}
	if !time.Now().Before(fresh.expiresAt) {
		return p.credentialAfterRefreshError(errors.New("Volcengine STS returned an expired credential"))
	}
	p.credential = *fresh
	return p.credential, nil
}

// credentialAfterRefreshError deliberately ignores the context: on this path it
// is only the refresh timeout, and a timed-out refresh is exactly when the
// still-valid cached credential must keep being served.
func (p *cachedVolcengineTOSCredentialProvider) credentialAfterRefreshError(refreshErr error) (volcengineTOSCredential, error) {
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

// volcengineTOSCredentials adapts the provider chain to vtos.Credentials. It
// replaces vtos.NewFederationCredentials, which calls STS eagerly in the
// constructor and keeps signing with an expired credential once a refresh fails.
type volcengineTOSCredentials struct {
	provider       volcengineTOSCredentialProvider
	refreshTimeout time.Duration

	mu      sync.Mutex
	lastErr error
}

func (c *volcengineTOSCredentials) resolve() (vtos.Credential, error) {
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

// Credential implements vtos.Credentials, which cannot return an error: a
// failed resolve yields an empty Credential and records the error for
// tosCredentialGuardTransport to surface.
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

// Authorization prefix the TOS SDK emits when it signs with an empty AccessKeyID.
const tosSigV4EmptyAccessKeyPrefix = "TOS4-HMAC-SHA256 Credential=/"

// tosCredentialGuardTransport fails a request the SDK signed with an empty
// AccessKeyID (credential resolution failed) instead of sending it for a 403.
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

type volcengineSTSClient interface {
	assumeRoleWithOIDC(ctx context.Context, tokenFile, roleTRN string) (*volcengineTOSCredential, error)
	assumeRole(ctx context.Context, base volcengineTOSCredential, roleTRN string) (*volcengineTOSCredential, error)
}

// volcengineSTS owns its http.Client: the volcengine SDK mutates the client it
// is handed (Transport, Proxy), so sharing one across providers would race.
type volcengineSTS struct {
	region     string
	httpClient *http.Client
	oidcURL    string
}

func newVolcengineSTS(region string) *volcengineSTS {
	return &volcengineSTS{
		region: region,
		// Backstop above tosCredentialRefreshTimeout.
		httpClient: &http.Client{Timeout: 12 * time.Second},
		oidcURL:    "https://" + volcengineSTSHost(region) + "/?Action=AssumeRoleWithOIDC&Version=2018-01-01",
	}
}

func volcengineSTSHost(region string) string {
	return "sts." + region + ".volcengineapi.com"
}

func volcengineExpiry(raw string) time.Time {
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw)); err == nil {
		return parsed
	}
	return time.Now().Add(tosAssumeRoleDuration)
}

// assumeRoleWithOIDC bypasses the SDK's OIDCCredentialsProvider, which sends
// DurationSeconds+60 and is rejected by a role at the 3600s default maximum.
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
		// The SDK's error type has no Unwrap; re-attach the context error so
		// callers can errors.Is(err, context.DeadlineExceeded).
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
