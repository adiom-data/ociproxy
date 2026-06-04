package ociproxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Proxy is an http.Handler that enforces repository-scoped access before
// forwarding OCI Distribution API requests to an upstream registry.
type Proxy[S any] struct {
	Auth           Authenticator[S]
	TargetResolver TargetResolver[S]
	Authorizer     Authorizer[S]
	Tokens         TokenCodec
	Client         *http.Client
	ExternalBase   *url.URL
	RedirectMode   RedirectMode
}

// RedirectMode controls how upstream storage redirects are handled.
type RedirectMode int

const (
	// RedirectModePassThrough returns upstream redirects to the client. This is
	// the default because OCI clients already know how to replay upload bodies
	// across 307 redirects, while a streaming proxy cannot rewind request bodies.
	RedirectModePassThrough RedirectMode = iota

	// RedirectModeExperimentalProxyStream attempts to follow upstream storage
	// redirects and stream the original request body through the proxy. This is
	// suitable for replay-safe requests like blob pulls, but upload requests can
	// fail if the upstream consumes any body bytes before returning the redirect.
	RedirectModeExperimentalProxyStream
)

func New[S any](auth Authenticator[S], targetResolver TargetResolver[S], authorizer Authorizer[S], tokenKey []byte) (*Proxy[S], error) {
	if auth == nil {
		return nil, errors.New("ociproxy: authenticator is required")
	}
	if targetResolver == nil {
		return nil, errors.New("ociproxy: target resolver is required")
	}
	if authorizer == nil {
		authorizer = AllowAll[S]()
	}
	return &Proxy[S]{
		Auth:           auth,
		TargetResolver: targetResolver,
		Authorizer:     authorizer,
		Tokens: TokenCodec{
			Primary: tokenKey,
			TTL:     30 * time.Minute,
		},
	}, nil
}

func (p *Proxy[S]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := p.serve(w, r); err != nil {
		status := http.StatusForbidden
		var se ErrorStatus
		if errors.As(err, &se) {
			status = se.StatusCode()
		}
		if status < 400 {
			status = http.StatusForbidden
		}
		http.Error(w, http.StatusText(status), status)
	}
}

func (p *Proxy[S]) serve(w http.ResponseWriter, r *http.Request) error {
	if p.Auth == nil || p.TargetResolver == nil || p.Authorizer == nil {
		return statusError{status: http.StatusInternalServerError, err: "proxy is not configured"}
	}

	rt, err := parseRoute(r)
	if err != nil {
		return statusError{status: http.StatusNotFound, err: err.Error()}
	}

	state := uploadState{}
	if rt.kind == routeUploadSession {
		state, err = p.Tokens.Verify(rt.session)
		if err != nil {
			return statusError{status: http.StatusForbidden, err: err.Error()}
		}
		if state.Repo != rt.repo {
			return statusError{status: http.StatusForbidden, err: "upload token repository mismatch"}
		}
	}

	authResult, err := p.Auth.AuthenticateOCI(r.Context(), AuthRequest{
		Request:  r,
		Accesses: rt.access,
	})
	if err != nil {
		return err
	}
	target, err := p.TargetResolver.ResolveOCITarget(r.Context(), TargetRequest[S]{
		Session:  authResult.Session,
		Request:  r,
		Accesses: rt.access,
	})
	if err != nil {
		return err
	}
	if rt.kind == routeUploadSession {
		upstream, err := upstreamFromState(state)
		if err != nil {
			return statusError{status: http.StatusForbidden, err: err.Error()}
		}
		target.BaseURL = upstream
		target.RepoMapper = exactRepoMapper{
			Public:   state.Repo,
			Upstream: state.UpstreamRepo,
		}
	}
	if err := validateTarget(target); err != nil {
		return statusError{status: http.StatusForbidden, err: err.Error()}
	}
	if err := p.Authorizer.AuthorizeOCI(r.Context(), PolicyRequest[S]{
		Session:  authResult.Session,
		Target:   target,
		Request:  r,
		Accesses: rt.access,
	}); err != nil {
		return err
	}

	upReq, err := p.upstreamRequest(r, rt, state, target)
	if err != nil {
		return statusError{status: http.StatusBadGateway, err: err.Error()}
	}

	resp, err := p.do(upReq)
	if err != nil {
		return statusError{status: http.StatusBadGateway, err: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return statusError{status: http.StatusBadGateway, err: "upstream authorization failed"}
	}

	if isRedirect(resp.StatusCode) && p.RedirectMode == RedirectModeExperimentalProxyStream {
		resp, err = p.followStorageRedirect(r.Context(), r, resp)
		if err != nil {
			return statusError{status: http.StatusBadGateway, err: err.Error()}
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return statusError{status: http.StatusBadGateway, err: "redirect target authorization failed"}
		}
	}

	locationHandled := false
	if rt.kind == routeUploadStart && resp.StatusCode == http.StatusAccepted {
		if err := p.rewriteUploadLocation(resp, rt.repo, target); err != nil {
			return statusError{status: http.StatusBadGateway, err: err.Error()}
		}
		locationHandled = true
	}
	if rt.kind == routeUploadSession && resp.StatusCode == http.StatusAccepted && resp.Header.Get("Location") != "" {
		uploadID, rawQuery, err := extractUploadLocation(resp.Header.Get("Location"))
		if err != nil {
			return statusError{status: http.StatusBadGateway, err: err.Error()}
		}
		if uploadID != "" {
			state.UploadID = uploadID
		}
		state.Query = rawQuery
		token, err := p.Tokens.Sign(uploadState{
			UploadID:     state.UploadID,
			Repo:         state.Repo,
			UpstreamRepo: state.UpstreamRepo,
			Upstream:     state.Upstream,
			Query:        state.Query,
			Expiry:       state.Expiry,
		})
		if err != nil {
			return statusError{status: http.StatusInternalServerError, err: err.Error()}
		}
		resp.Header.Set("Location", p.clientUploadLocation(r, rt.repo, token, ""))
		locationHandled = true
	}
	if !isRedirect(resp.StatusCode) && !locationHandled {
		p.rewriteRegistryLocation(resp, target)
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	return nil
}

func validateTarget(target Target) error {
	if target.BaseURL == nil || target.BaseURL.Scheme == "" || target.BaseURL.Host == "" {
		return errors.New("target base URL is required")
	}
	return nil
}

func upstreamFromState(state uploadState) (*url.URL, error) {
	if state.Upstream == "" {
		return nil, errors.New("upload token missing upstream")
	}
	u, err := url.Parse(state.Upstream)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (p *Proxy[S]) upstreamRequest(in *http.Request, rt route, state uploadState, target Target) (*http.Request, error) {
	upstream := target.BaseURL
	u := *upstream
	u.Path = singleJoiningSlash(upstream.Path, upstreamPathForRoute(rt, state, target))
	u.RawQuery = in.URL.RawQuery

	if rt.kind == routeUploadSession {
		u.RawQuery = mergeRawQuery(state.Query, in.URL.RawQuery)
	}
	if rt.kind == routeUploadStart && rt.mount {
		q := u.Query()
		q.Set("from", target.UpstreamRepo(rt.from))
		u.RawQuery = q.Encode()
	}

	if rt.kind == routeUploadStart && rt.mount {
		// The resolver only returns on allowed access. If callers want denied
		// mounts to fall back to a plain upload, they should deny only the source
		// pull access and wrap this handler to retry without mount parameters.
	}

	req, err := http.NewRequestWithContext(in.Context(), in.Method, u.String(), in.Body)
	if err != nil {
		return nil, err
	}
	copyHeader(req.Header, in.Header)
	if target.Authorization != "" {
		req.Header.Set("Authorization", target.Authorization)
	} else {
		req.Header.Del("Authorization")
	}
	req.Host = upstream.Host
	if mayCarryUploadBody(rt, in) && req.Header.Get("Expect") == "" {
		req.Header.Set("Expect", "100-continue")
	}
	return req, nil
}

func upstreamPathForRoute(rt route, state uploadState, target Target) string {
	repo := target.UpstreamRepo(rt.repo)
	switch rt.kind {
	case routeBase:
		return "/v2/"
	case routeManifest:
		return routePath(repo, "manifests", rt.ref)
	case routeBlob:
		return routePath(repo, "blobs", rt.ref)
	case routeUploadStart:
		return routePath(repo, "blobs", "uploads", "")
	case routeUploadSession:
		upstreamRepo := state.UpstreamRepo
		if upstreamRepo == "" {
			upstreamRepo = repo
		}
		return routePath(upstreamRepo, "blobs", "uploads", state.UploadID)
	default:
		return routePath(repo)
	}
}

func (p *Proxy[S]) followStorageRedirect(ctx context.Context, original *http.Request, redirect *http.Response) (*http.Response, error) {
	loc := redirect.Header.Get("Location")
	if loc == "" {
		return nil, errors.New("redirect without Location")
	}
	redirect.Body.Close()
	req, err := http.NewRequestWithContext(ctx, original.Method, loc, original.Body)
	if err != nil {
		return nil, err
	}
	copyHeader(req.Header, original.Header)
	req.Header.Del("Authorization")
	return p.do(req)
}

func (p *Proxy[S]) rewriteUploadLocation(resp *http.Response, repo string, target Target) error {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	uploadID, rawQuery, err := extractUploadLocation(loc)
	if err != nil {
		return err
	}
	token, err := p.Tokens.Sign(uploadState{
		UploadID:     uploadID,
		Repo:         repo,
		UpstreamRepo: target.UpstreamRepo(repo),
		Upstream:     target.BaseURL.String(),
		Query:        rawQuery,
	})
	if err != nil {
		return err
	}
	resp.Header.Set("Location", p.clientUploadLocation(resp.Request, repo, token, ""))
	return nil
}

func (p *Proxy[S]) clientUploadLocation(r *http.Request, repo, token, rawQuery string) string {
	u := url.URL{Path: routePath(repo, "blobs", "uploads", token), RawQuery: rawQuery}
	if p.ExternalBase != nil {
		base := *p.ExternalBase
		base.Path = singleJoiningSlash(base.Path, u.Path)
		base.RawQuery = u.RawQuery
		return base.String()
	}
	return u.String()
}

func extractUploadLocation(loc string) (string, string, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(strings.TrimRight(u.Path, "/"), "/")
	if len(parts) == 0 {
		return "", "", errors.New("invalid upload Location")
	}
	uploadID := parts[len(parts)-1]
	if uploadID == "" || uploadID == "uploads" {
		return "", "", errors.New("upload Location missing session id")
	}
	return uploadID, u.RawQuery, nil
}

func (p *Proxy[S]) rewriteRegistryLocation(resp *http.Response, target Target) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil {
		return
	}
	if u.Host != "" && !sameEndpoint(u, target.BaseURL) {
		return
	}
	if u.Host == "" && !strings.HasPrefix(u.Path, "/v2/") {
		return
	}
	if rewritten, ok := rewriteLocationRepo(u.Path, target); ok {
		u.Path = rewritten
	}
	if p.ExternalBase != nil {
		base := *p.ExternalBase
		base.Path = singleJoiningSlash(base.Path, u.Path)
		base.RawQuery = u.RawQuery
		resp.Header.Set("Location", base.String())
		return
	}
	u.Scheme = ""
	u.Host = ""
	resp.Header.Set("Location", u.String())
}

func rewriteLocationRepo(path string, target Target) (string, bool) {
	if target.RepoMapper == nil {
		return path, false
	}
	rt, err := parseRoute(&http.Request{Method: http.MethodGet, URL: &url.URL{Path: path}})
	if err != nil || rt.repo == "" {
		return path, false
	}
	clientRepo, ok := target.ClientRepo(rt.repo)
	if ok {
		return replaceRepoInPath(path, rt.repo, clientRepo), true
	}
	return path, false
}

type exactRepoMapper struct {
	Public   string
	Upstream string
}

func (m exactRepoMapper) UpstreamRepo(repo string) string {
	if repo == m.Public {
		return m.Upstream
	}
	return repo
}

func (m exactRepoMapper) ClientRepo(repo string) (string, bool) {
	if repo == m.Upstream {
		return m.Public, true
	}
	return repo, true
}

func replaceRepoInPath(path, fromRepo, toRepo string) string {
	from := "/v2/" + fromRepo + "/"
	if strings.HasPrefix(path, from) {
		return "/v2/" + toRepo + "/" + strings.TrimPrefix(path, from)
	}
	if path == strings.TrimSuffix(from, "/") {
		return "/v2/" + toRepo
	}
	return path
}

func sameEndpoint(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func (p *Proxy[S]) do(req *http.Request) (*http.Response, error) {
	return p.clientNoRedirect().Do(req)
}

func (p *Proxy[S]) clientNoRedirect() *http.Client {
	if p.Client != nil {
		return &http.Client{
			Transport: p.Client.Transport,
			Timeout:   p.Client.Timeout,
			Jar:       p.Client.Jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{ExpectContinueTimeout: time.Second},
	}
}

func mayCarryUploadBody(rt route, r *http.Request) bool {
	return rt.kind == routeUploadSession &&
		(r.Method == http.MethodPatch || r.Method == http.MethodPut) &&
		(r.ContentLength != 0 || r.Header.Get("Content-Length") != "0")
}

func isRedirect(status int) bool {
	return status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		dst.Del(k)
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func mergeRawQuery(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "&" + b
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}

type statusError struct {
	status int
	err    string
}

func (e statusError) Error() string   { return e.err }
func (e statusError) StatusCode() int { return e.status }
