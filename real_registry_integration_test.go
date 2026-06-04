//go:build integration

package ociproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestRealRegistryPushAndPullThroughProxy(t *testing.T) {
	registryURL := os.Getenv("OCIPROXY_REGISTRY_URL")
	if registryURL == "" {
		t.Skip("set OCIPROXY_REGISTRY_URL to run real registry integration test")
	}
	testRepo := os.Getenv("OCIPROXY_TEST_REPO")
	if testRepo == "" {
		testRepo = "tenant-a/app"
	}
	upstreamAuth := os.Getenv("OCIPROXY_UPSTREAM_AUTH")
	dockerConfig := []byte(os.Getenv("OCIPROXY_DOCKER_CONFIG_JSON"))
	repoPrefix := os.Getenv("OCIPROXY_UPSTREAM_REPO_PREFIX")
	upstream, err := url.Parse(registryURL)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := New[struct{}](
		AuthenticatorFunc[struct{}](func(ctx context.Context, req AuthRequest) (AuthResult[struct{}], error) {
			if req.Request.Header.Get("Authorization") != "Bearer local" {
				return AuthResult[struct{}]{}, integrationStatusError{http.StatusUnauthorized, "missing local auth"}
			}
			return AuthResult[struct{}]{}, nil
		}),
		TargetResolverFunc[struct{}](func(ctx context.Context, req TargetRequest[struct{}]) (Target, error) {
			auth := upstreamAuth
			if auth == "" && len(dockerConfig) > 0 {
				auth, err = AuthorizationFromDockerConfig(ctx, nil, upstream, dockerConfig, []RegistryScope{
					RepositoryScope(prefixedRepo(repoPrefix, testRepo), "pull", "push"),
				})
				if err != nil {
					return Target{}, err
				}
			}
			target := Target{BaseURL: upstream, Authorization: auth}
			if repoPrefix != "" {
				target.RepoMapper = PrefixRepoMapper(repoPrefix)
			}
			return target, nil
		}),
		AuthorizerFunc[struct{}](func(ctx context.Context, req PolicyRequest[struct{}]) error {
			for _, access := range req.Accesses {
				if access.Repo != testRepo {
					return integrationStatusError{http.StatusForbidden, "wrong repo"}
				}
			}
			return nil
		}),
		[]byte("real-registry-key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OCIPROXY_EXPERIMENTAL_PROXY_STREAM_REDIRECTS") != "" {
		proxy.RedirectMode = RedirectModeExperimentalProxyStream
	}
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	var redirects []string
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = append(redirects, req.Method+" "+req.URL.String())
			return nil
		},
	}
	layer := []byte("hello from ociproxy\n")
	layerDigest := digest(layer)
	layerURL := pushBlob(t, client, proxyServer.URL, testRepo, layer, layerDigest)
	if !strings.HasPrefix(layerURL, "/v2/"+testRepo+"/blobs/"+layerDigest) {
		t.Fatalf("blob Location = %q", layerURL)
	}

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["` + layerDigest + `"]},"config":{}}`)
	configDigest := digest(config)
	pushBlob(t, client, proxyServer.URL, testRepo, config, configDigest)

	manifest := imageManifest(configDigest, len(config), layerDigest, len(layer))
	manifestDigest := digest(manifest)
	putManifest(t, client, proxyServer.URL, testRepo, "v1", manifest)

	gotManifest := get(t, client, proxyServer.URL+"/v2/"+testRepo+"/manifests/v1", "application/vnd.docker.distribution.manifest.v2+json")
	if digest(gotManifest) != manifestDigest {
		t.Fatalf("manifest digest = %s, want %s", digest(gotManifest), manifestDigest)
	}

	gotLayer := get(t, client, proxyServer.URL+"/v2/"+testRepo+"/blobs/"+layerDigest, "")
	if !bytes.Equal(gotLayer, layer) {
		t.Fatalf("pulled layer = %q", string(gotLayer))
	}

	req, err := http.NewRequest(http.MethodGet, proxyServer.URL+"/v2/tenant-b/app/manifests/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forbidden repo status = %d", resp.StatusCode)
	}
	if os.Getenv("OCIPROXY_VERIFY_UPSTREAM_REPO") != "" {
		verifyAuth := upstreamAuth
		if verifyAuth == "" && len(dockerConfig) > 0 {
			verifyAuth, err = AuthorizationFromDockerConfig(context.Background(), nil, upstream, dockerConfig, []RegistryScope{
				RepositoryScope(prefixedRepo(repoPrefix, testRepo), "pull"),
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		verifyUpstreamRepo(t, client, registryURL, prefixedRepo(repoPrefix, testRepo), verifyAuth)
	}
	if os.Getenv("OCIPROXY_REQUIRE_REDIRECT") != "" && len(redirects) == 0 {
		t.Fatal("expected at least one redirect, saw none")
	}
	if os.Getenv("OCIPROXY_FORBID_CLIENT_REDIRECT") != "" && len(redirects) != 0 {
		t.Fatalf("expected no client redirects, saw %d: %v", len(redirects), redirects)
	}
	for _, redirect := range redirects {
		t.Logf("followed redirect: %s", redirect)
	}
}

func pushBlob(t *testing.T, client *http.Client, base, repo string, body []byte, dgst string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/v2/"+repo+"/blobs/uploads/", nil)
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
		t.Fatalf("blob start status = %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("blob start missing Location")
	}

	req, err = http.NewRequest(http.MethodPatch, absoluteURL(base, loc), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("blob patch status = %d: %s", resp.StatusCode, responseBody(t, resp))
	}
	resp.Body.Close()
	if next := resp.Header.Get("Location"); next != "" {
		loc = next
	}

	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	req, err = http.NewRequest(http.MethodPut, absoluteURL(base, loc)+sep+"digest="+dgst, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("blob commit status = %d: %s", resp.StatusCode, responseBody(t, resp))
	}
	resp.Body.Close()
	return resp.Header.Get("Location")
}

func putManifest(t *testing.T, client *http.Client, base, repo, ref string, manifest []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, base+"/v2/"+repo+"/manifests/"+ref, bytes.NewReader(manifest))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("manifest put status = %d: %s", resp.StatusCode, responseBody(t, resp))
	}
	resp.Body.Close()
}

func get(t *testing.T, client *http.Client, target, accept string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer local")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d", target, resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func verifyUpstreamRepo(t *testing.T, client *http.Client, registryURL, repo, upstreamAuth string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(registryURL, "/")+"/v2/"+repo+"/manifests/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if upstreamAuth != "" {
		req.Header.Set("Authorization", upstreamAuth)
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upstream repo %s status = %d", repo, resp.StatusCode)
	}
}

func imageManifest(configDigest string, configSize int, layerDigest string, layerSize int) []byte {
	doc := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"size":      configSize,
			"digest":    configDigest,
		},
		"layers": []map[string]any{
			{
				"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
				"size":      layerSize,
				"digest":    layerDigest,
			},
		},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func absoluteURL(base, loc string) string {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	return strings.TrimRight(base, "/") + loc
}

func prefixedRepo(prefix, repo string) string {
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return repo
	}
	return prefix + "/" + repo
}

func responseBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
