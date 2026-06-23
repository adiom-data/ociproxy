package ociproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUploadLocationIsTokenizedAndBoundToRepo(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/tenant-a/app/blobs/uploads/" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		w.Header().Set("Location", "/v2/tenant-a/app/blobs/uploads/upstream-uuid?_state=abc")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "/v2/tenant-a/app/blobs/uploads/", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/v2/tenant-a/app/blobs/uploads/") {
		t.Fatalf("unexpected Location: %s", loc)
	}
	if strings.Contains(loc, "upstream-uuid") {
		t.Fatalf("upstream uuid leaked in Location: %s", loc)
	}
	token := strings.TrimPrefix(strings.Split(loc, "?")[0], "/v2/tenant-a/app/blobs/uploads/")
	state, err := proxy.Tokens.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if state.UploadID != "upstream-uuid" || state.Repo != "tenant-a/app" || state.Query != "_state=abc" {
		t.Fatalf("bad state: %+v", state)
	}
}

func TestUploadTokenRepoMismatchIsForbidden(t *testing.T) {
	proxy := newTestProxy(t, "https://upstream.example")
	token, err := proxy.Tokens.Sign(uploadState{
		UploadID: "uuid",
		Repo:     "tenant-a/app",
		Expiry:   time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/v2/tenant-b/app/blobs/uploads/"+token, strings.NewReader("x"))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCrossRepoMountRequiresTargetPushAndSourcePull(t *testing.T) {
	var got []Access
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/v2/tenant-b/repo/blobs/uploads/uuid")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream.URL)
	proxy.Authorizer = AuthorizerFunc[struct{}](func(ctx context.Context, req PolicyRequest[struct{}]) error {
		got = req.Accesses
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/v2/tenant-b/repo/blobs/uploads/?mount=sha256:abc&from=common/base", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if len(got) != 2 {
		t.Fatalf("access count = %d: %+v", len(got), got)
	}
	if got[0] != (Access{Action: ActionPush, Repo: "tenant-b/repo"}) {
		t.Fatalf("target access = %+v", got[0])
	}
	if got[1] != (Access{Action: ActionPull, Repo: "common/base"}) {
		t.Fatalf("source access = %+v", got[1])
	}
}

func TestCanonicalRepoRejectsEncodedSlash(t *testing.T) {
	proxy := newTestProxy(t, "https://upstream.example")
	req := httptest.NewRequest(http.MethodGet, "/v2/tenant-a%2fsecret/app/manifests/latest", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRedirectPassThroughIsDefault(t *testing.T) {
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("storage redirect was followed")
	}))
	defer storage.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", storage.URL+"/upload")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream.URL)
	proxy.Client = &http.Client{}
	req := httptest.NewRequest(http.MethodPatch, "/v2/tenant-a/app/blobs/uploads/"+uploadTokenForUpstream(t, proxy, "tenant-a/app", "uuid", upstream.URL), strings.NewReader("layer"))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Location") != storage.URL+"/upload" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}
}

func TestRepoMayContainReservedWords(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/v2/team/blobs/app/manifests/latest", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotPath != "/v2/team/blobs/app/manifests/latest" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestTagsListRequiresPullAndForwardsQuery(t *testing.T) {
	var gotPath string
	var gotQuery string
	var gotAccesses []Access
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"tenant-a/app","tags":["v1"]}`))
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream.URL)
	proxy.Authorizer = AuthorizerFunc[struct{}](func(ctx context.Context, req PolicyRequest[struct{}]) error {
		gotAccesses = req.Accesses
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v2/tenant-a/app/tags/list?n=10&last=v0", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotPath != "/v2/tenant-a/app/tags/list" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotQuery != "n=10&last=v0" {
		t.Fatalf("query = %q", gotQuery)
	}
	if len(gotAccesses) != 1 || gotAccesses[0] != (Access{Action: ActionPull, Repo: "tenant-a/app"}) {
		t.Fatalf("accesses = %+v", gotAccesses)
	}
}

func TestMalformedMountDoesNotReachUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("malformed mount reached upstream")
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "/v2/tenant-a/app/blobs/uploads/?mount=sha256:abc&from=Bad/Repo", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestUpstreamAuthChallengeIsHidden(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"https://upstream.example/token\"")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/v2/tenant-a/app/manifests/latest", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("leaked challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestUploadSessionStaysOnSelectedDynamicUpstream(t *testing.T) {
	var patchBackend string
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patchBackend = "a"
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backendA.Close()

	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Location", "/v2/tenant-a/app/blobs/uploads/backend-b-upload")
			w.WriteHeader(http.StatusAccepted)
		case http.MethodPatch:
			patchBackend = "b"
			if r.URL.Path != "/v2/tenant-a/app/blobs/uploads/backend-b-upload" {
				t.Fatalf("patch path = %q", r.URL.Path)
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backendB.Close()

	backendAURL, err := url.Parse(backendA.URL)
	if err != nil {
		t.Fatal(err)
	}
	backendBURL, err := url.Parse(backendB.URL)
	if err != nil {
		t.Fatal(err)
	}

	useBackendB := true
	proxy, err := New[struct{}](
		AuthenticatorFunc[struct{}](func(context.Context, AuthRequest) (AuthResult[struct{}], error) {
			return AuthResult[struct{}]{}, nil
		}),
		TargetResolverFunc[struct{}](func(ctx context.Context, req TargetRequest[struct{}]) (Target, error) {
			if useBackendB {
				return Target{Authorization: "Bearer hidden", BaseURL: backendBURL}, nil
			}
			return Target{Authorization: "Bearer hidden", BaseURL: backendAURL}, nil
		}),
		AllowAll[struct{}](),
		[]byte("test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	start := httptest.NewRequest(http.MethodPost, "/v2/tenant-a/app/blobs/uploads/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, start)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start status = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	useBackendB = false

	patch := httptest.NewRequest(http.MethodPatch, loc, strings.NewReader("x"))
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, patch)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("patch status = %d", rec.Code)
	}
	if patchBackend != "b" {
		t.Fatalf("patch backend = %q", patchBackend)
	}
}

func TestNewRequiresTargetSelectedUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New[struct{}](
		AuthenticatorFunc[struct{}](func(context.Context, AuthRequest) (AuthResult[struct{}], error) {
			return AuthResult[struct{}]{}, nil
		}),
		TargetResolverFunc[struct{}](func(ctx context.Context, req TargetRequest[struct{}]) (Target, error) {
			return Target{BaseURL: upstreamURL}, nil
		}),
		AllowAll[struct{}](),
		[]byte("test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/tenant-a/app/manifests/latest", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRepoMappingPrefixesUpstreamAndRewritesLocations(t *testing.T) {
	var paths []string
	var gotFrom string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		gotFrom = r.URL.Query().Get("from")
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Location", "/v2/remote/123/local/asdf/blobs/uploads/upstream-upload?_state=abc")
			w.WriteHeader(http.StatusAccepted)
		case http.MethodPatch:
			w.Header().Set("Location", "/v2/remote/123/local/asdf/blobs/uploads/upstream-upload?_state=def")
			w.WriteHeader(http.StatusAccepted)
		case http.MethodPut:
			w.Header().Set("Location", "/v2/remote/123/local/asdf/blobs/sha256:abc")
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New[struct{}](
		AuthenticatorFunc[struct{}](func(context.Context, AuthRequest) (AuthResult[struct{}], error) {
			return AuthResult[struct{}]{}, nil
		}),
		TargetResolverFunc[struct{}](func(context.Context, TargetRequest[struct{}]) (Target, error) {
			return Target{
				BaseURL:    upstreamURL,
				RepoMapper: PrefixRepoMapper("remote/123"),
			}, nil
		}),
		AllowAll[struct{}](),
		[]byte("test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v2/local/asdf/blobs/uploads/?mount=sha256:abc&from=shared/base/python", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start status = %d", rec.Code)
	}
	if paths[0] != "/v2/remote/123/local/asdf/blobs/uploads/" {
		t.Fatalf("start upstream path = %q", paths[0])
	}
	if gotFrom != "remote/123/shared/base/python" {
		t.Fatalf("from = %q", gotFrom)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/v2/local/asdf/blobs/uploads/") {
		t.Fatalf("start Location = %q", loc)
	}

	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, loc, strings.NewReader("x")))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("patch status = %d", rec.Code)
	}
	if paths[1] != "/v2/remote/123/local/asdf/blobs/uploads/upstream-upload" {
		t.Fatalf("patch upstream path = %q", paths[1])
	}
	loc = rec.Header().Get("Location")

	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, loc+"?digest=sha256:abc", nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("commit status = %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/v2/local/asdf/blobs/sha256:abc" {
		t.Fatalf("commit Location = %q", got)
	}
}

func TestRepoMappingPrefixesTagsList(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New[struct{}](
		AuthenticatorFunc[struct{}](func(context.Context, AuthRequest) (AuthResult[struct{}], error) {
			return AuthResult[struct{}]{}, nil
		}),
		TargetResolverFunc[struct{}](func(context.Context, TargetRequest[struct{}]) (Target, error) {
			return Target{
				BaseURL:    upstreamURL,
				RepoMapper: PrefixRepoMapper("remote/123"),
			}, nil
		}),
		AllowAll[struct{}](),
		[]byte("test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/local/asdf/tags/list", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotPath != "/v2/remote/123/local/asdf/tags/list" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestRepoMapperCanLeaveSharedReposIdentity(t *testing.T) {
	mapper := RepoMapperFunc{
		Upstream: func(repo string) string {
			if strings.HasPrefix(repo, "shared/") {
				return repo
			}
			return "remote/123/" + repo
		},
		Public: func(repo string) (string, bool) {
			if strings.HasPrefix(repo, "shared/") {
				return repo, true
			}
			return strings.CutPrefix(repo, "remote/123/")
		},
	}

	if got := mapper.UpstreamRepo("local/asdf"); got != "remote/123/local/asdf" {
		t.Fatalf("mapped local repo = %q", got)
	}
	if got := mapper.UpstreamRepo("shared/base/python"); got != "shared/base/python" {
		t.Fatalf("mapped shared repo = %q", got)
	}
	if got, ok := mapper.ClientRepo("remote/123/local/asdf"); !ok || got != "local/asdf" {
		t.Fatalf("client local repo = %q, %v", got, ok)
	}
	if got, ok := mapper.ClientRepo("shared/base/python"); !ok || got != "shared/base/python" {
		t.Fatalf("client shared repo = %q, %v", got, ok)
	}
}

func newTestProxy(t *testing.T, upstream string) *Proxy[struct{}] {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &Proxy[struct{}]{
		Auth: AuthenticatorFunc[struct{}](func(context.Context, AuthRequest) (AuthResult[struct{}], error) {
			return AuthResult[struct{}]{}, nil
		}),
		TargetResolver: TargetResolverFunc[struct{}](func(context.Context, TargetRequest[struct{}]) (Target, error) {
			return Target{Authorization: "Bearer hidden", BaseURL: u}, nil
		}),
		Authorizer: AllowAll[struct{}](),
		Tokens:     TokenCodec{Primary: []byte("test-key"), TTL: time.Minute},
		Client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func uploadToken(t *testing.T, proxy *Proxy[struct{}], repo, uploadID string) string {
	t.Helper()
	return uploadTokenForUpstream(t, proxy, repo, uploadID, "https://upstream.example")
}

func uploadTokenForUpstream(t *testing.T, proxy *Proxy[struct{}], repo, uploadID, upstream string) string {
	t.Helper()
	token, err := proxy.Tokens.Sign(uploadState{
		UploadID:     uploadID,
		Repo:         repo,
		UpstreamRepo: repo,
		Upstream:     upstream,
		Expiry:       time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}
