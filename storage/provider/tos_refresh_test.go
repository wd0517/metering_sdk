package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	vtos "github.com/volcengine/ve-tos-golang-sdk/v2/tos"
)

type tosRefreshReadResult struct {
	credential volcengineTOSCredential
	err        error
}

func readTOSCredentialAsync(p *cachedVolcengineTOSCredentialProvider, ctx context.Context) <-chan tosRefreshReadResult {
	result := make(chan tosRefreshReadResult, 1)
	go func() {
		credential, err := p.GetCredential(ctx)
		result <- tosRefreshReadResult{credential: credential, err: err}
	}()
	return result
}

func receiveTOSCredential(t *testing.T, result <-chan tosRefreshReadResult) tosRefreshReadResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("credential caller remained blocked")
		return tosRefreshReadResult{}
	}
}

func awaitTOSRefreshSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("credential refresh did not reach the expected state")
	}
}

func tosRefreshDone(t *testing.T, p *cachedVolcengineTOSCredentialProvider) <-chan struct{} {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	require.NotNil(t, p.inflight)
	return p.inflight.done
}

// waitForTOSRefresh waits for publication of a refresh already in flight.
func waitForTOSRefresh(t *testing.T, p *cachedVolcengineTOSCredentialProvider) {
	t.Helper()
	p.mu.Lock()
	inflight := p.inflight
	p.mu.Unlock()
	if inflight != nil {
		awaitTOSRefreshSignal(t, inflight.done)
	}
}

func TestTOSRefreshValidCacheReturnsBeforeSTSCompletes(t *testing.T) {
	old := stsCredential("old", time.Minute)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	p := &cachedVolcengineTOSCredentialProvider{
		duration:   time.Hour,
		credential: *old,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			close(started)
			select {
			case <-release:
				return stsCredential("new", time.Hour), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := readTOSCredentialAsync(p, ctx)
	awaitTOSRefreshSignal(t, started)
	got := receiveTOSCredential(t, result)
	require.NoError(t, got.err)
	require.Equal(t, *old, got.credential)
	done := tosRefreshDone(t, p)
	// Other callers keep using the valid credential while the one refresh runs.
	const concurrency = 16
	results := make([]<-chan tosRefreshReadResult, 0, concurrency)
	for i := 0; i < concurrency; i++ {
		results = append(results, readTOSCredentialAsync(p, ctx))
	}
	for _, result := range results {
		got := receiveTOSCredential(t, result)
		require.NoError(t, got.err)
		require.Equal(t, *old, got.credential)
	}
	unblock()
	awaitTOSRefreshSignal(t, done)
	fresh, err := p.GetCredential(ctx)
	require.NoError(t, err)
	require.Equal(t, "new-ak", fresh.accessKey)
}

func TestTOSRefreshCancellationDoesNotCancelSharedColdRefresh(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	sharedCanceled := make(chan struct{}, 1)
	var calls atomic.Int32
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	p := &cachedVolcengineTOSCredentialProvider{
		duration: time.Hour,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			if calls.Add(1) == 1 {
				close(started)
			}
			select {
			case <-release:
				return stsCredential("shared", time.Hour), nil
			case <-ctx.Done():
				sharedCanceled <- struct{}{}
				return nil, ctx.Err()
			}
		},
	}
	firstCtx, cancel := context.WithCancel(context.Background())
	first := readTOSCredentialAsync(p, firstCtx)
	awaitTOSRefreshSignal(t, started)
	cancel()
	got := receiveTOSCredential(t, first)
	require.ErrorIs(t, got.err, context.Canceled)
	select {
	case <-sharedCanceled:
		t.Fatal("canceling one waiter canceled the shared STS refresh")
	default:
	}
	second := readTOSCredentialAsync(p, context.Background())
	unblock()
	got = receiveTOSCredential(t, second)
	require.NoError(t, got.err)
	require.Equal(t, "shared-ak", got.credential.accessKey)
	require.Equal(t, int32(1), calls.Load())
}

// Done is evaluated when GetCredential reaches its wait select. Observing it
// lets concurrent tests release STS only after every caller joined the refresh.
type tosRefreshWaiterContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *tosRefreshWaiterContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestTOSRefreshConcurrentColdAndExpiredCallersShareResult(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expired bool
		fail    bool
	}{
		{name: "cold-success"},
		{name: "expired-success", expired: true},
		{name: "cold-failure", fail: true},
		{name: "expired-failure", expired: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			var calls atomic.Int32
			refreshErr := errors.New("STS unavailable")
			p := &cachedVolcengineTOSCredentialProvider{
				duration: time.Hour,
				refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
					if calls.Add(1) == 1 {
						close(started)
					}
					select {
					case <-release:
						if tc.fail {
							return nil, refreshErr
						}
						return stsCredential("shared", time.Hour), nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				},
			}
			if tc.expired {
				p.credential = *stsCredential("expired", -time.Minute)
			}
			const concurrency = 8
			results := make([]<-chan tosRefreshReadResult, 0, concurrency)
			waiting := make([]<-chan struct{}, 0, concurrency)
			for i := 0; i < concurrency; i++ {
				ctx := &tosRefreshWaiterContext{Context: context.Background(), waiting: make(chan struct{})}
				waiting = append(waiting, ctx.waiting)
				results = append(results, readTOSCredentialAsync(p, ctx))
			}
			awaitTOSRefreshSignal(t, started)
			for _, callerWaiting := range waiting {
				awaitTOSRefreshSignal(t, callerWaiting)
			}
			unblock()
			for _, result := range results {
				got := receiveTOSCredential(t, result)
				if tc.fail {
					require.ErrorIs(t, got.err, refreshErr)
					require.Empty(t, got.credential.accessKey)
				} else {
					require.NoError(t, got.err)
					require.Equal(t, "shared-ak", got.credential.accessKey)
				}
			}
			require.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestTOSRefreshExpiredCacheNeverHidesRefreshError(t *testing.T) {
	refreshErr := errors.New("STS unavailable")
	p := &cachedVolcengineTOSCredentialProvider{
		duration:   time.Hour,
		credential: *stsCredential("expired", -time.Minute),
		refresh:    func(context.Context) (*volcengineTOSCredential, error) { return nil, refreshErr },
	}
	got, err := p.GetCredential(context.Background())
	require.ErrorIs(t, err, refreshErr)
	require.Empty(t, got.accessKey)
}

func TestTOSRefreshUploadUsesValidCredentialsWhileSTSIsBlocked(t *testing.T) {
	requests := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		requests <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	proxyURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	httpTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer httpTransport.CloseIdleConnections()
	started := make(chan struct{})
	release := make(chan struct{})
	callbackDone := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var calls atomic.Int32
	sts := &fakeVolcengineSTS{
		assumeRoleFn: func(ctx context.Context, _ volcengineTOSCredential, _ string) (*volcengineTOSCredential, error) {
			if calls.Add(1) == 1 {
				return stsCredential("cached", time.Minute), nil
			}
			close(started)
			defer close(callbackDone)
			select {
			case <-release:
				return stsCredential("new", time.Hour), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	p, err := newTOSProvider(&ProviderConfig{
		Type: ProviderTypeTOS, Bucket: testTOSBucket, Region: testTOSRegion,
		Endpoint: "http://tos.example.invalid",
		TOS:      &TOSConfig{AccessKey: "base-ak", SecretAccessKey: "base-sk", AssumeRoleARN: testTOSRoleTRN},
	}, sts, vtos.NewDefaultTransportWithClient(http.Client{Transport: httpTransport}))
	require.NoError(t, err)
	require.NoError(t, p.Upload(context.Background(), "metering/ru/first.json.gz", strings.NewReader("first")))
	require.Contains(t, <-requests, "Credential=cached-ak/")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- p.Upload(ctx, "metering/ru/second.json.gz", strings.NewReader("second")) }()
	awaitTOSRefreshSignal(t, started)
	select {
	case err := <-result:
		require.NoError(t, err, "valid credentials must permit upload before the caller deadline while STS remains blocked")
	case <-time.After(2 * time.Second):
		t.Fatal("upload waited for STS instead of using the valid credential")
	}
	require.NoError(t, ctx.Err())
	require.Contains(t, <-requests, "Credential=cached-ak/")
	require.Equal(t, int32(2), calls.Load())
	unblock()
	awaitTOSRefreshSignal(t, callbackDone)
}

func TestTOSRefreshValidCacheFailureBacksOffThenRetries(t *testing.T) {
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	secondStarted := make(chan struct{})
	secondRelease := make(chan struct{})
	var firstOnce, secondOnce sync.Once
	unblockFirst := func() { firstOnce.Do(func() { close(firstRelease) }) }
	unblockSecond := func() { secondOnce.Do(func() { close(secondRelease) }) }
	t.Cleanup(unblockFirst)
	t.Cleanup(unblockSecond)
	var calls atomic.Int32
	old := stsCredential("old", time.Minute)
	p := &cachedVolcengineTOSCredentialProvider{
		duration:   time.Hour,
		credential: *old,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			switch calls.Add(1) {
			case 1:
				close(firstStarted)
				select {
				case <-firstRelease:
					return nil, errors.New("STS temporarily unavailable")
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			case 2:
				close(secondStarted)
				select {
				case <-secondRelease:
					return stsCredential("recovered", time.Hour), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			default:
				return nil, errors.New("unexpected extra refresh")
			}
		},
	}
	got, err := p.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, *old, got)
	awaitTOSRefreshSignal(t, firstStarted)
	firstDone := tosRefreshDone(t, p)
	unblockFirst()
	awaitTOSRefreshSignal(t, firstDone)
	p.mu.Lock()
	retryAfter := p.retryAfter
	p.mu.Unlock()
	require.WithinDuration(t, time.Now().Add(30*time.Second), retryAfter, time.Second)
	for i := 0; i < 16; i++ {
		got, err := p.GetCredential(context.Background())
		require.NoError(t, err)
		require.Equal(t, *old, got)
	}
	require.Equal(t, int32(1), calls.Load(), "backoff must suppress repeated failing STS requests")

	// Move only the backoff clock to avoid a 30-second wall-clock sleep.
	p.mu.Lock()
	p.retryAfter = time.Now().Add(-time.Second)
	p.mu.Unlock()
	got, err = p.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, *old, got)
	awaitTOSRefreshSignal(t, secondStarted)
	secondDone := tosRefreshDone(t, p)
	unblockSecond()
	awaitTOSRefreshSignal(t, secondDone)
	got, err = p.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, "recovered-ak", got.accessKey)
	require.Equal(t, int32(2), calls.Load())
}

func TestTOSRefreshExpiryBypassesFailureBackoff(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var calls atomic.Int32
	refreshErr := errors.New("STS unavailable")
	p := &cachedVolcengineTOSCredentialProvider{
		duration:   time.Hour,
		credential: *stsCredential("old", time.Minute),
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			if calls.Add(1) == 1 {
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return nil, refreshErr
		},
	}
	got, err := p.GetCredential(context.Background())
	require.NoError(t, err)
	require.Equal(t, "old-ak", got.accessKey)
	awaitTOSRefreshSignal(t, started)
	done := tosRefreshDone(t, p)
	unblock()
	awaitTOSRefreshSignal(t, done)
	p.mu.Lock()
	retryAfter := p.retryAfter
	p.credential.expiresAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	require.True(t, retryAfter.After(time.Now()))
	got, err = p.GetCredential(context.Background())
	require.ErrorIs(t, err, refreshErr)
	require.Empty(t, got.accessKey, "expired credentials must not be returned during failure backoff")
	require.Equal(t, int32(2), calls.Load(), "an expired cache must try refreshing even during backoff")
}

func TestTOSRefreshColdRequestUsesIndependentBoundedTimeout(t *testing.T) {
	const refreshTimeout = 50 * time.Millisecond
	p := &cachedVolcengineTOSCredentialProvider{
		duration:       time.Hour,
		refreshTimeout: refreshTimeout,
		refresh: func(ctx context.Context) (*volcengineTOSCredential, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	callerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := p.GetCredential(callerCtx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Empty(t, got.accessKey)
	require.NoError(t, callerCtx.Err(), "the refresh deadline must be independent from the longer caller deadline")
}
