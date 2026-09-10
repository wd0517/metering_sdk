package provider

import (
	"context"
	"encoding/json"
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
	tosAssumeRoleDuration       = 3600 * time.Second
	tosCredentialRefreshTimeout = 10 * time.Second
	envVolcengineOIDCTokenFile  = "VOLCENGINE_OIDC_TOKEN_FILE"
	envVolcengineOIDCRoleTRN    = "VOLCENGINE_OIDC_ROLE_TRN"
	envVolcengineRegion         = "REGION"
)

var (
	assumeVolcengineRole = assumeVolcengineRoleWithSTS
	oidcSTSURL           = volcengineOIDCSTSURL
	oidcHTTPClient       = &http.Client{Timeout: 10 * time.Second}
)

// TOSProvider Volcengine TOS storage provider implementation.
type TOSProvider struct {
	client *vtos.ClientV2
	bucket string
	prefix string
}

// NewTOSProvider creates a new TOS storage provider.
func NewTOSProvider(providerConfig *ProviderConfig) (*TOSProvider, error) {
	if providerConfig.Type != ProviderTypeTOS {
		return nil, fmt.Errorf("invalid provider type: %s, expected: %s", providerConfig.Type, ProviderTypeTOS)
	}
	if providerConfig.Bucket == "" {
		return nil, fmt.Errorf("bucket name is required for TOS provider")
	}

	endpoint, err := buildTOSEndpoint(providerConfig.Region, providerConfig.Endpoint)
	if err != nil {
		return nil, err
	}

	credentials, err := newVolcengineTOSCredentials(providerConfig)
	if err != nil {
		return nil, err
	}

	client, err := vtos.NewClientV2(endpoint,
		vtos.WithRegion(providerConfig.Region),
		vtos.WithCredentials(credentials),
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

func buildTOSEndpoint(region, endpoint string) (string, error) {
	if value := strings.TrimSpace(endpoint); value != "" {
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
		if value == "" {
			return "", fmt.Errorf("invalid TOS endpoint")
		}
		return value, nil
	}
	region = strings.TrimSpace(region)
	if region == "" {
		return "", fmt.Errorf("region is required for TOS provider when endpoint is not set")
	}
	return fmt.Sprintf("tos-%s.ivolces.com", region), nil
}

func buildVolcengineSTSEndpoint(region string) string {
	return fmt.Sprintf("sts.%s.volcengineapi.com", strings.TrimSpace(region))
}

func volcengineOIDCSTSURL(region string) string {
	return "https://" + buildVolcengineSTSEndpoint(region) + "/?Action=AssumeRoleWithOIDC&Version=2018-01-01"
}

func resolveVolcengineRegion(region string) string {
	region = strings.TrimSpace(region)
	if region != "" {
		return region
	}
	return strings.TrimSpace(os.Getenv(envVolcengineRegion))
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

type oidcVolcengineTOSCredentialProvider struct {
	mu        sync.Mutex
	tokenFile string
	roleTRN   string
	region    string
	duration  time.Duration

	credential volcengineTOSCredential
	expiresAt  time.Time
}

func (p *oidcVolcengineTOSCredentialProvider) GetCredential(ctx context.Context) (volcengineTOSCredential, error) {
	if err := ctx.Err(); err != nil {
		return volcengineTOSCredential{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	refreshAt := p.expiresAt.Add(-p.duration / 10)
	if p.credential.accessKey != "" && time.Now().Before(refreshAt) {
		return p.credential, nil
	}

	cred, err := assumeVolcengineRoleWithOIDC(ctx, p.tokenFile, p.roleTRN, p.region, p.duration)
	if err != nil {
		if p.credential.accessKey != "" && time.Now().Before(p.expiresAt) {
			return p.credential, nil
		}
		return volcengineTOSCredential{}, err
	}
	p.credential = *cred
	p.expiresAt = cred.expiresAt
	return p.credential, nil
}

type assumeRoleVolcengineTOSCredentialProvider struct {
	mu           sync.Mutex
	baseProvider volcengineTOSCredentialProvider
	roleTRN      string
	region       string
	duration     time.Duration

	credential volcengineTOSCredential
	expiresAt  time.Time
}

func (p *assumeRoleVolcengineTOSCredentialProvider) GetCredential(ctx context.Context) (volcengineTOSCredential, error) {
	if err := ctx.Err(); err != nil {
		return volcengineTOSCredential{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	refreshAt := p.expiresAt.Add(-p.duration / 10)
	if p.credential.accessKey != "" && time.Now().Before(refreshAt) {
		return p.credential, nil
	}

	baseCred, err := p.baseProvider.GetCredential(ctx)
	if err != nil {
		return p.credentialAfterRefreshError(ctx, err)
	}

	result, err := assumeVolcengineRole(ctx, baseCred, p.roleTRN, defaultTOSAssumeRoleSessionName, p.duration, p.region)
	if err != nil {
		return p.credentialAfterRefreshError(ctx, err)
	}

	p.credential = volcengineTOSCredential{
		accessKey:    result.accessKey,
		secretKey:    result.secretKey,
		sessionToken: result.sessionToken,
		expiresAt:    result.expiresAt,
	}
	p.expiresAt = result.expiresAt
	if p.expiresAt.IsZero() || p.expiresAt.Unix() <= 0 {
		p.expiresAt = time.Now().Add(p.duration)
	}
	return p.credential, nil
}

func (p *assumeRoleVolcengineTOSCredentialProvider) credentialAfterRefreshError(ctx context.Context, refreshErr error) (volcengineTOSCredential, error) {
	if err := ctx.Err(); err != nil {
		return volcengineTOSCredential{}, err
	}
	if p.credential.accessKey != "" && time.Now().Before(p.expiresAt) {
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

func newVolcengineTOSCredentialProvider(cfg *TOSConfig, region string) (volcengineTOSCredentialProvider, error) {
	region = resolveVolcengineRegion(region)

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

	return &assumeRoleVolcengineTOSCredentialProvider{
		baseProvider: baseProvider,
		roleTRN:      strings.TrimSpace(cfg.AssumeRoleARN),
		region:       region,
		duration:     tosAssumeRoleDuration,
	}, nil
}

type tosFederationTokenProvider struct {
	provider volcengineTOSCredentialProvider
	duration time.Duration
}

func (p *tosFederationTokenProvider) FederationToken() (*vtos.FederationToken, error) {
	// The TOS credentials interface has no request context. Bound both STS hops
	// so a stalled refresh cannot block storage operations indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), tosCredentialRefreshTimeout)
	defer cancel()
	cred, err := p.provider.GetCredential(ctx)
	if err != nil {
		return nil, err
	}
	if cred.accessKey == "" || cred.secretKey == "" {
		return nil, fmt.Errorf("Volcengine TOS credentials are empty")
	}
	expiration := cred.expiresAt
	if expiration.IsZero() {
		expiration = time.Now().Add(p.duration)
	}
	return &vtos.FederationToken{
		Credential: vtos.Credential{
			AccessKeyID:     cred.accessKey,
			AccessKeySecret: cred.secretKey,
			SecurityToken:   cred.sessionToken,
		},
		Expiration: expiration,
	}, nil
}

func newVolcengineTOSCredentials(providerConfig *ProviderConfig) (vtos.Credentials, error) {
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
	creds, err := vtos.NewFederationCredentials(&tosFederationTokenProvider{
		provider: provider,
		duration: tosAssumeRoleDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve TOS credentials: %w", err)
	}
	return creds, nil
}

func newVolcengineOIDCCredentialProvider(region string) (*oidcVolcengineTOSCredentialProvider, error) {
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
	region = resolveVolcengineRegion(region)
	if region == "" {
		return nil, fmt.Errorf("region is required for Volcengine OIDC")
	}
	return &oidcVolcengineTOSCredentialProvider{
		tokenFile: tokenFile,
		roleTRN:   roleTRN,
		region:    region,
		duration:  tosAssumeRoleDuration,
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

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
	region = resolveVolcengineRegion(region)
	if region == "" {
		return nil, fmt.Errorf("region is required to assume a Volcengine role")
	}

	sess, err := session.NewSession(volcengine.NewConfig().
		WithRegion(region).
		WithEndpoint(buildVolcengineSTSEndpoint(region)).
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
