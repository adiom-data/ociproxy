package ociproxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAuthorizationFromDockerConfigBearerChallenge(t *testing.T) {
	var tokenRequestPath string
	var tokenRequestAuth string
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequestPath = r.URL.String()
		tokenRequestAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"registry-token"}`))
	}))
	defer authServer.Close()

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+authServer.URL+`/token",service="registry.example"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer registry.Close()

	registryURL, err := url.Parse(registry.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`{"auths":{"` + registryURL.Host + `":{"auth":"` + base64.StdEncoding.EncodeToString([]byte("user:pass")) + `"}}}`)

	got, err := AuthorizationFromDockerConfig(context.Background(), nil, registryURL, cfg, []RegistryScope{
		RepositoryScope("tenant-a/app", "pull", "push"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "Bearer registry-token" {
		t.Fatalf("auth = %q", got)
	}
	if tokenRequestAuth != "Basic dXNlcjpwYXNz" {
		t.Fatalf("token basic auth = %q", tokenRequestAuth)
	}
	if tokenRequestPath != "/token?scope=repository%3Atenant-a%2Fapp%3Apull%2Cpush&service=registry.example" {
		t.Fatalf("token request path = %q", tokenRequestPath)
	}
}

func TestAuthorizationFromDockerConfigRegistryToken(t *testing.T) {
	registryURL, err := url.Parse("https://registry.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`{"auths":{"registry.example":{"registrytoken":"static-token"}}}`)

	got, err := AuthorizationFromDockerConfig(context.Background(), nil, registryURL, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Bearer static-token" {
		t.Fatalf("auth = %q", got)
	}
}
