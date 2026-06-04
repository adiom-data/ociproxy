package ociproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIntegrationPushFlowWithPassThroughStorageRedirect(t *testing.T) {
	var storageBody string
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Fatalf("storage method = %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		storageBody = string(body)
		w.Header().Set("Location", "/storage/uploaded")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer storage.Close()

	upstream := newFakeRegistry(t, storage.URL)
	defer upstream.Close()

	proxy := newIntegrationProxy(t, upstream.URL, func(accesses []Access) bool {
		return hasAccess(accesses, ActionPush, "tenant-a/app")
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, proxyServer.URL+"/v2/tenant-a/app/blobs/uploads/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	uploadLoc := resp.Header.Get("Location")
	if !strings.HasPrefix(uploadLoc, "/v2/tenant-a/app/blobs/uploads/") {
		t.Fatalf("start Location = %q", uploadLoc)
	}
	if strings.Contains(uploadLoc, "upstream-upload") {
		t.Fatalf("upstream upload id leaked in Location: %q", uploadLoc)
	}

	req, err = http.NewRequest(http.MethodPatch, proxyServer.URL+uploadLoc, strings.NewReader("layer bytes"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("patch status = %d", resp.StatusCode)
	}
	if storageBody != "layer bytes" {
		t.Fatalf("storage body = %q", storageBody)
	}

	req, err = http.NewRequest(http.MethodPut, proxyServer.URL+uploadLoc+"?digest=sha256:abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("commit status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/v2/tenant-a/app/blobs/sha256:abc" {
		t.Fatalf("commit Location = %q", got)
	}

	req, err = http.NewRequest(http.MethodPut, proxyServer.URL+"/v2/tenant-a/app/manifests/v1", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("manifest status = %d", resp.StatusCode)
	}

	if upstream.requestCount() == 0 {
		t.Fatal("upstream did not receive requests")
	}
}

func TestIntegrationCrossRepoMountPolicy(t *testing.T) {
	upstream := newFakeRegistry(t, "https://storage.example")
	defer upstream.Close()

	proxy := newIntegrationProxy(t, upstream.URL, func(accesses []Access) bool {
		return hasAccess(accesses, ActionPush, "tenant-a/app") &&
			hasAccess(accesses, ActionPull, "common/base")
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	req, err := http.NewRequest(http.MethodPost, proxyServer.URL+"/v2/tenant-a/app/blobs/uploads/?mount=sha256:base&from=common/base", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("allowed mount status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/v2/tenant-a/app/blobs/sha256:base" {
		t.Fatalf("allowed mount Location = %q", got)
	}

	req, err = http.NewRequest(http.MethodPost, proxyServer.URL+"/v2/tenant-a/app/blobs/uploads/?mount=sha256:secret&from=secret/base", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied mount status = %d", resp.StatusCode)
	}
	if upstream.seenMount("secret/base") {
		t.Fatal("denied source mount reached upstream")
	}
}

type fakeRegistry struct {
	*httptest.Server
	t          *testing.T
	storageURL string
	mu         sync.Mutex
	requests   []string
	mounts     []string
}

func newFakeRegistry(t *testing.T, storageURL string) *fakeRegistry {
	fr := &fakeRegistry{t: t, storageURL: storageURL}
	fr.Server = httptest.NewServer(http.HandlerFunc(fr.handle))
	return fr
}

func (fr *fakeRegistry) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer hidden" {
		fr.t.Fatalf("upstream Authorization = %q", r.Header.Get("Authorization"))
	}
	fr.mu.Lock()
	fr.requests = append(fr.requests, r.Method+" "+r.URL.String())
	fr.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v2/tenant-a/app/blobs/uploads/" && r.URL.Query().Get("mount") != "":
		from := r.URL.Query().Get("from")
		fr.mu.Lock()
		fr.mounts = append(fr.mounts, from)
		fr.mu.Unlock()
		w.Header().Set("Location", "/v2/tenant-a/app/blobs/"+r.URL.Query().Get("mount"))
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPost && r.URL.Path == "/v2/tenant-a/app/blobs/uploads/":
		w.Header().Set("Location", "/v2/tenant-a/app/blobs/uploads/upstream-upload?_state=abc")
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodPatch && r.URL.Path == "/v2/tenant-a/app/blobs/uploads/upstream-upload":
		if r.URL.Query().Get("_state") != "abc" {
			fr.t.Fatalf("missing upstream state query: %q", r.URL.RawQuery)
		}
		w.Header().Set("Location", fr.storageURL+"/upload")
		w.WriteHeader(http.StatusTemporaryRedirect)
	case r.Method == http.MethodPut && r.URL.Path == "/v2/tenant-a/app/blobs/uploads/upstream-upload":
		if r.URL.Query().Get("digest") != "sha256:abc" || r.URL.Query().Get("_state") != "abc" {
			fr.t.Fatalf("commit query = %q", r.URL.RawQuery)
		}
		w.Header().Set("Location", fr.Server.URL+"/v2/tenant-a/app/blobs/sha256:abc")
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut && r.URL.Path == "/v2/tenant-a/app/manifests/v1":
		w.Header().Set("Location", fr.Server.URL+"/v2/tenant-a/app/manifests/v1")
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, fmt.Sprintf("unexpected upstream request: %s %s", r.Method, r.URL.String()), http.StatusNotFound)
	}
}

func (fr *fakeRegistry) requestCount() int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return len(fr.requests)
}

func (fr *fakeRegistry) seenMount(from string) bool {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	for _, mount := range fr.mounts {
		if mount == from {
			return true
		}
	}
	return false
}

func newIntegrationProxy(t *testing.T, upstream string, allow func([]Access) bool) *Proxy[struct{}] {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &Proxy[struct{}]{
		Auth: AuthenticatorFunc[struct{}](func(ctx context.Context, req AuthRequest) (AuthResult[struct{}], error) {
			if req.Request.Header.Get("Authorization") != "Bearer local" {
				return AuthResult[struct{}]{}, integrationStatusError{http.StatusUnauthorized, "missing local auth"}
			}
			return AuthResult[struct{}]{}, nil
		}),
		TargetResolver: TargetResolverFunc[struct{}](func(ctx context.Context, req TargetRequest[struct{}]) (Target, error) {
			return Target{Authorization: "Bearer hidden", BaseURL: u}, nil
		}),
		Authorizer: AuthorizerFunc[struct{}](func(ctx context.Context, req PolicyRequest[struct{}]) error {
			if !allow(req.Accesses) {
				return integrationStatusError{http.StatusForbidden, "denied"}
			}
			return nil
		}),
		Tokens: TokenCodec{Primary: []byte("integration-key"), TTL: time.Minute},
	}
}

func hasAccess(accesses []Access, action Action, repo string) bool {
	for _, access := range accesses {
		if access.Action == action && access.Repo == repo {
			return true
		}
	}
	return false
}

type integrationStatusError struct {
	status int
	err    string
}

func (e integrationStatusError) Error() string   { return e.err }
func (e integrationStatusError) StatusCode() int { return e.status }
