package ociproxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrUnauthenticated = errors.New("ociproxy: unauthenticated")
	ErrForbidden       = errors.New("ociproxy: forbidden")
)

// Action is an OCI repository permission required by a request.
type Action string

const (
	ActionPull Action = "pull"
	ActionPush Action = "push"
)

// Access describes one client-facing repository permission required to forward
// a request.
type Access struct {
	Action Action
	Repo   string
}

// AuthRequest is passed to an Authenticator after the proxy has parsed the OCI
// route and inferred the client-facing repository accesses.
type AuthRequest struct {
	Request  *http.Request
	Accesses []Access
}

// AuthResult carries application-defined session data into target resolution
// and authorization.
type AuthResult[S any] struct {
	Session S
}

// Authenticator verifies the local client request.
type Authenticator[S any] interface {
	AuthenticateOCI(context.Context, AuthRequest) (AuthResult[S], error)
}

type AuthenticatorFunc[S any] func(context.Context, AuthRequest) (AuthResult[S], error)

func (f AuthenticatorFunc[S]) AuthenticateOCI(ctx context.Context, req AuthRequest) (AuthResult[S], error) {
	return f(ctx, req)
}

// Target describes where an authorized request should be forwarded. RepoMapper
// maps client-facing repository paths to upstream repository paths for the
// current request. A nil mapper uses the same path upstream.
type Target struct {
	BaseURL       *url.URL
	Authorization string
	RepoMapper    RepoMapper
}

// UpstreamRepo returns the upstream repository path for a client-facing repo.
func (t Target) UpstreamRepo(repo string) string {
	if t.RepoMapper != nil {
		return t.RepoMapper.UpstreamRepo(repo)
	}
	return repo
}

// ClientRepo returns the client-facing repository path for an upstream repo.
func (t Target) ClientRepo(repo string) (string, bool) {
	if t.RepoMapper != nil {
		return t.RepoMapper.ClientRepo(repo)
	}
	return repo, true
}

// RepoMapper translates repositories for one request/session. Implementations
// should be deterministic for the lifetime of the request.
type RepoMapper interface {
	UpstreamRepo(clientRepo string) string
	ClientRepo(upstreamRepo string) (clientRepo string, ok bool)
}

type RepoMapperFunc struct {
	Upstream func(clientRepo string) string
	Public   func(upstreamRepo string) (string, bool)
}

func (m RepoMapperFunc) UpstreamRepo(repo string) string {
	if m.Upstream != nil {
		return m.Upstream(repo)
	}
	return repo
}

func (m RepoMapperFunc) ClientRepo(repo string) (string, bool) {
	if m.Public != nil {
		return m.Public(repo)
	}
	return repo, true
}

type PrefixRepoMapper string

func (m PrefixRepoMapper) UpstreamRepo(repo string) string {
	prefix := strings.Trim(string(m), "/")
	if prefix == "" {
		return repo
	}
	return prefix + "/" + repo
}

func (m PrefixRepoMapper) ClientRepo(repo string) (string, bool) {
	prefix := strings.Trim(string(m), "/")
	if prefix == "" {
		return repo, true
	}
	return strings.CutPrefix(repo, prefix+"/")
}

// TargetRequest is passed to a TargetResolver after local authentication.
type TargetRequest[S any] struct {
	Session  S
	Request  *http.Request
	Accesses []Access
}

// TargetResolver selects the upstream registry and upstream Authorization header
// for an authenticated request.
type TargetResolver[S any] interface {
	ResolveOCITarget(context.Context, TargetRequest[S]) (Target, error)
}

type TargetResolverFunc[S any] func(context.Context, TargetRequest[S]) (Target, error)

func (f TargetResolverFunc[S]) ResolveOCITarget(ctx context.Context, req TargetRequest[S]) (Target, error) {
	return f(ctx, req)
}

// PolicyRequest is passed to an Authorizer after authentication and target
// resolution. Accesses always contain client-facing repository paths.
type PolicyRequest[S any] struct {
	Session  S
	Target   Target
	Request  *http.Request
	Accesses []Access
}

// Authorizer decides whether an authenticated request may reach the selected
// upstream registry.
type Authorizer[S any] interface {
	AuthorizeOCI(context.Context, PolicyRequest[S]) error
}

type AuthorizerFunc[S any] func(context.Context, PolicyRequest[S]) error

func (f AuthorizerFunc[S]) AuthorizeOCI(ctx context.Context, req PolicyRequest[S]) error {
	return f(ctx, req)
}

// AllowAll allows every authenticated request.
func AllowAll[S any]() Authorizer[S] {
	return AuthorizerFunc[S](func(context.Context, PolicyRequest[S]) error {
		return nil
	})
}

// ErrorStatus can be implemented by hook errors to control the response status.
// Errors without a status are returned as 403 Forbidden.
type ErrorStatus interface {
	error
	StatusCode() int
}
