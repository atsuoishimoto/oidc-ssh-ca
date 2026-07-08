package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newDiscoveryServer serves a minimal OIDC discovery document whose
// issuer is the server's own URL. hook, if non-nil, runs at the start
// of every discovery request; returning false makes the server respond
// 500 instead of the document.
func newDiscoveryServer(t *testing.T, hook func() bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if hook != nil && !hook() {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// A discovery in flight for one issuer must not delay requests for an
// issuer that is already cached (issue #55).
func TestProviderCacheHitDoesNotWaitForSlowDiscovery(t *testing.T) {
	fast := newDiscoveryServer(t, nil)

	inFlight := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	slow := newDiscoveryServer(t, func() bool {
		once.Do(func() { close(inFlight) })
		<-release
		return true
	})
	// Registered after the server's own Close cleanup so it runs first,
	// unblocking the handler before Close waits for it.
	t.Cleanup(func() { close(release) })

	v := NewRemoteVerifier()
	ctx := context.Background()
	if _, err := v.provider(ctx, fast.URL); err != nil {
		t.Fatal(err)
	}

	go v.provider(ctx, slow.URL)
	<-inFlight

	done := make(chan error, 1)
	go func() {
		_, err := v.provider(ctx, fast.URL)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cached-issuer lookup blocked behind another issuer's discovery")
	}
}

func TestProviderConcurrentMissesShareOneFetch(t *testing.T) {
	var calls atomic.Int32
	srv := newDiscoveryServer(t, func() bool {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return true
	})

	v := NewRemoteVerifier()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.provider(context.Background(), srv.URL); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("discovery fetched %d times, want 1", got)
	}
}

func TestProviderCachesDiscoveryFailure(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	srv := newDiscoveryServer(t, func() bool {
		calls.Add(1)
		return !fail.Load()
	})

	v := NewRemoteVerifier()
	current := time.Now()
	v.now = func() time.Time { return current }
	ctx := context.Background()

	if _, err := v.provider(ctx, srv.URL); err == nil {
		t.Fatal("first discovery should fail")
	}
	if _, err := v.provider(ctx, srv.URL); err == nil {
		t.Fatal("second call should return the cached failure")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("discovery fetched %d times within retry delay, want 1", got)
	}

	fail.Store(false)
	current = current.Add(discoveryRetryDelay)
	if _, err := v.provider(ctx, srv.URL); err != nil {
		t.Fatalf("discovery after retry delay: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("discovery fetched %d times after retry delay, want 2", got)
	}

	// The recovered provider is cached like any other success.
	if _, err := v.provider(ctx, srv.URL); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("discovery fetched %d times after success, want 2", got)
	}
}
