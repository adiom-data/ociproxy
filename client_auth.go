package ociproxy

import (
	"net/http"
	"strings"
)

// BearerToken returns the token from an Authorization: Bearer header.
func BearerToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, token, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// BasicPasswordToken returns the password from HTTP Basic auth. This is useful
// for Docker/Kubernetes imagePullSecrets where the password carries a local
// proxy token and the username is a tenant hint or ignored.
func BasicPasswordToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	_, password, ok := r.BasicAuth()
	return password, ok && password != ""
}

// LocalToken returns a client-facing token from either Authorization: Bearer or
// the password field of HTTP Basic auth. Bearer takes precedence.
func LocalToken(r *http.Request) (string, bool) {
	if token, ok := BearerToken(r); ok {
		return token, true
	}
	return BasicPasswordToken(r)
}
