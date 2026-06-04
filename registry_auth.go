package ociproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DockerConfigJSON is the subset of Docker config.json / Kubernetes
// .dockerconfigjson used for registry authentication.
type DockerConfigJSON struct {
	Auths map[string]DockerAuthConfig `json:"auths"`
}

type DockerAuthConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Auth          string `json:"auth,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}

// RegistryScope describes a Bearer-token scope requested from a registry auth
// service, for example repository:tenant-a/app:pull,push.
type RegistryScope struct {
	Type    string
	Name    string
	Actions []string
}

func RepositoryScope(repo string, actions ...string) RegistryScope {
	return RegistryScope{Type: "repository", Name: repo, Actions: actions}
}

func (s RegistryScope) String() string {
	return s.Type + ":" + s.Name + ":" + strings.Join(s.Actions, ",")
}

// AuthorizationFromDockerConfig returns an Authorization header value for the
// registry and scopes using Docker config credentials. It supports static
// registry tokens and the standard Docker Registry v2 Bearer challenge flow.
func AuthorizationFromDockerConfig(ctx context.Context, client *http.Client, registry *url.URL, dockerConfig []byte, scopes []RegistryScope) (string, error) {
	if registry == nil || registry.Scheme == "" || registry.Host == "" {
		return "", errors.New("registry URL with scheme and host is required")
	}
	var cfg DockerConfigJSON
	if err := json.Unmarshal(dockerConfig, &cfg); err != nil {
		return "", err
	}
	auth, ok := dockerAuthForHost(cfg, registry.Host)
	if !ok {
		return "", fmt.Errorf("no docker credentials for %s", registry.Host)
	}
	return AuthorizationFromDockerAuth(ctx, client, registry, auth, scopes)
}

// AuthorizationFromDockerAuth returns an Authorization header value for a single
// Docker auth entry.
func AuthorizationFromDockerAuth(ctx context.Context, client *http.Client, registry *url.URL, auth DockerAuthConfig, scopes []RegistryScope) (string, error) {
	if registry == nil || registry.Scheme == "" || registry.Host == "" {
		return "", errors.New("registry URL with scheme and host is required")
	}
	if auth.RegistryToken != "" {
		return "Bearer " + auth.RegistryToken, nil
	}
	if auth.IdentityToken != "" {
		return "Bearer " + auth.IdentityToken, nil
	}
	username, password, err := auth.Basic()
	if err != nil {
		return "", err
	}
	challenge, err := registryChallenge(ctx, client, registry)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(challenge.Scheme, "Bearer") {
		return basicAuthorization(username, password), nil
	}
	token, err := requestBearerToken(ctx, client, challenge, username, password, scopes)
	if err != nil {
		return "", err
	}
	return "Bearer " + token, nil
}

func (a DockerAuthConfig) Basic() (string, string, error) {
	if a.Username != "" || a.Password != "" {
		return a.Username, a.Password, nil
	}
	if a.Auth == "" {
		return "", "", errors.New("docker auth entry has no username/password or auth")
	}
	decoded, err := base64.StdEncoding.DecodeString(a.Auth)
	if err != nil {
		return "", "", err
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", errors.New("docker auth field is not username:password")
	}
	return username, password, nil
}

type registryAuthChallenge struct {
	Scheme string
	Params map[string]string
}

func registryChallenge(ctx context.Context, client *http.Client, registry *url.URL) (registryAuthChallenge, error) {
	u := *registry
	u.Path = singleJoiningSlash(registry.Path, "/v2/")
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return registryAuthChallenge{}, err
	}
	resp, err := httpClient(client).Do(req)
	if err != nil {
		return registryAuthChallenge{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return registryAuthChallenge{Scheme: "Basic"}, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return registryAuthChallenge{}, fmt.Errorf("registry challenge status %d", resp.StatusCode)
	}
	header := resp.Header.Get("WWW-Authenticate")
	if header == "" {
		return registryAuthChallenge{}, errors.New("registry challenge missing WWW-Authenticate")
	}
	return parseAuthChallenge(header)
}

func requestBearerToken(ctx context.Context, client *http.Client, challenge registryAuthChallenge, username, password string, scopes []RegistryScope) (string, error) {
	realm := challenge.Params["realm"]
	if realm == "" {
		return "", errors.New("bearer challenge missing realm")
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if service := challenge.Params["service"]; service != "" {
		q.Set("service", service)
	}
	for _, scope := range scopes {
		q.Add("scope", scope.String())
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password)
	resp, err := httpClient(client).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint status %d", resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("token response missing token")
}

func dockerAuthForHost(cfg DockerConfigJSON, host string) (DockerAuthConfig, bool) {
	for key, auth := range cfg.Auths {
		if dockerAuthKeyMatchesHost(key, host) {
			return auth, true
		}
	}
	return DockerAuthConfig{}, false
}

func dockerAuthKeyMatchesHost(key, host string) bool {
	key = strings.TrimSpace(key)
	if key == host {
		return true
	}
	u, err := url.Parse(key)
	return err == nil && u.Host == host
}

func parseAuthChallenge(header string) (registryAuthChallenge, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok {
		return registryAuthChallenge{Scheme: header, Params: map[string]string{}}, nil
	}
	return registryAuthChallenge{Scheme: scheme, Params: parseChallengeParams(rest)}, nil
}

func parseChallengeParams(input string) map[string]string {
	params := map[string]string{}
	for _, part := range splitChallengeParams(input) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		params[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return params
}

func splitChallengeParams(input string) []string {
	var parts []string
	start := 0
	inQuotes := false
	for i, ch := range input {
		switch ch {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				parts = append(parts, input[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, input[start:])
	return parts
}

func basicAuthorization(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func httpClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}
