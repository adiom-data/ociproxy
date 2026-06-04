package ociproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalTokenPrefersBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.SetBasicAuth("tenant-a", "basic-token")
	req.Header.Set("Authorization", "Bearer bearer-token")

	token, ok := LocalToken(req)
	if !ok {
		t.Fatal("missing token")
	}
	if token != "bearer-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestLocalTokenFromBasicPassword(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.SetBasicAuth("tenant-a", "local-token")

	token, ok := LocalToken(req)
	if !ok {
		t.Fatal("missing token")
	}
	if token != "local-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestBearerTokenRejectsEmptyToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Header.Set("Authorization", "Bearer ")

	if token, ok := BearerToken(req); ok {
		t.Fatalf("unexpected token = %q", token)
	}
}
