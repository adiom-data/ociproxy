# ociproxy

`ociproxy` is a Go library for building a stateless OCI Distribution API
authorization proxy.

The library handles OCI route parsing, repository-path binding for multi-step
blob uploads, upload-session token signing, upstream request forwarding, and
redirect behavior. The application using the library owns local credential
validation, target selection, policy decisions, and hidden upstream registry
credential selection.

```go
proxy, err := ociproxy.New[UserSession](
	ociproxy.AuthenticatorFunc[UserSession](func(ctx context.Context, req ociproxy.AuthRequest) (ociproxy.AuthResult[UserSession], error) {
		// Authenticate the local client and attach application session data.
		return ociproxy.AuthResult[UserSession]{Session: userSession}, nil
	}),
	ociproxy.TargetResolverFunc[UserSession](func(ctx context.Context, req ociproxy.TargetRequest[UserSession]) (ociproxy.Target, error) {
		// Select the upstream registry and hidden upstream Authorization header.
		upstream, err := url.Parse("https://registry.example.com")
		if err != nil {
			return ociproxy.Target{}, err
		}
		return ociproxy.Target{
			BaseURL:       upstream,
			Authorization: "Bearer hidden-upstream-token",
		}, nil
	}),
	ociproxy.AuthorizerFunc[UserSession](func(ctx context.Context, req ociproxy.PolicyRequest[UserSession]) error {
		// Authorize client-facing repository paths such as tenant-a/app.
		return nil
	}),
	[]byte("32+ bytes of signing key material"),
)
if err != nil {
	log.Fatal(err)
}

http.ListenAndServe(":8080", proxy)
```

## Security model

Every OCI request is parsed into required repository accesses:

- `GET`/`HEAD` manifests and blobs require `pull`.
- `PUT` manifests, blob upload starts, upload chunks, and upload commits require
  `push`.
- Cross-repository blob mounts require `push` on the target repository and
  `pull` on the `from` repository.

Blob upload sessions are kept stateless by replacing the upstream upload UUID in
the client-facing `Location` with a signed token. `tokenKey` is the HMAC secret
used to sign those tokens. Later `PATCH` and `PUT` requests must present that
token, and the token repository must match the requested repository path. The
target-selected upstream registry is also bound into the upload token so later
upload chunks and commits continue against the same backend.

Upstream storage redirects are passed through by default. This keeps upload body
retries in the OCI client, which already has replayable access to the layer
bytes. The proxy has an opt-in `RedirectModeExperimentalProxyStream` mode for
proxying storage redirects itself. It is suitable for replay-safe requests such
as blob pulls, but upload requests can fail if the upstream consumes any body
bytes before returning the redirect.

The token is signed, not encrypted. If upstream upload IDs are sensitive in your
environment, wrap `TokenCodec` with an authenticated-encryption codec before
exposing tokens to clients.

## Integration testing

The default test suite uses in-process HTTP fakes:

```sh
go test ./...
```

To test against a real Docker Distribution registry:

```sh
docker run --rm -d --name ociproxy-registry-test -p 127.0.0.1:5001:5000 registry:2
OCIPROXY_REGISTRY_URL=http://127.0.0.1:5001 go test -tags=integration ./...
docker stop ociproxy-registry-test
```

For registries that require upstream auth, set `OCIPROXY_UPSTREAM_AUTH` to the
exact Authorization header value the proxy should send upstream. Set
`OCIPROXY_TEST_REPO` to override the default `tenant-a/app` test repo. Set
`OCIPROXY_REQUIRE_REDIRECT=1` to fail the real-registry test unless the client
observes at least one registry redirect through the proxy. Set
`OCIPROXY_EXPERIMENTAL_PROXY_STREAM_REDIRECTS=1` and
`OCIPROXY_FORBID_CLIENT_REDIRECT=1` to verify that the proxy can follow storage
redirects itself for replay-safe requests such as blob pulls.

`AuthorizationFromDockerConfig` can turn Docker `config.json` or Kubernetes
`.dockerconfigjson` credentials into an upstream Authorization header for a set
of repository scopes. It follows the standard registry Bearer challenge flow,
which is what registries such as ACR use behind normal image pulls.

`LocalToken` extracts a client-facing token from either `Authorization: Bearer`
or the password field of HTTP Basic auth, which is convenient for Docker and
Kubernetes image pull secrets.
