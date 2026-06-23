package ociproxy

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
)

var repoComponentRE = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

type routeKind int

const (
	routeUnknown routeKind = iota
	routeBase
	routeManifest
	routeBlob
	routeTagsList
	routeUploadStart
	routeUploadSession
)

type route struct {
	kind    routeKind
	repo    string
	ref     string
	session string
	access  []Access
	mount   bool
	from    string
}

func parseRoute(r *http.Request) (route, error) {
	p := r.URL.EscapedPath()
	lower := strings.ToLower(p)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return route{}, errors.New("encoded path separators are not allowed")
	}

	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		return route{kind: routeBase}, nil
	}
	if !strings.HasPrefix(r.URL.Path, "/v2/") {
		return route{}, errors.New("not an OCI v2 path")
	}

	rest := strings.TrimPrefix(r.URL.Path, "/v2/")
	parts := strings.Split(rest, "/")
	if len(parts) < 3 {
		return route{}, errors.New("invalid OCI route")
	}

	if idx := lastIndexMarker(parts, "manifests"); idx >= 1 && idx+1 < len(parts) {
		repo, err := canonicalRepo(parts[:idx])
		if err != nil {
			return route{}, err
		}
		rt := route{kind: routeManifest, repo: repo, ref: strings.Join(parts[idx+1:], "/")}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			rt.access = []Access{{Action: ActionPull, Repo: repo}}
		case http.MethodPut, http.MethodDelete:
			rt.access = []Access{{Action: ActionPush, Repo: repo}}
		default:
			return route{}, errors.New("unsupported manifest method")
		}
		return rt, nil
	}

	if idx := lastIndexMarker(parts, "tags"); idx >= 1 && idx+1 == len(parts)-1 && parts[idx+1] == "list" {
		if r.Method != http.MethodGet {
			return route{}, errors.New("unsupported tags list method")
		}
		repo, err := canonicalRepo(parts[:idx])
		if err != nil {
			return route{}, err
		}
		return route{kind: routeTagsList, repo: repo, access: []Access{{Action: ActionPull, Repo: repo}}}, nil
	}

	if idx := lastIndexMarker(parts, "blobs"); idx >= 1 && idx+1 < len(parts) {
		repo, err := canonicalRepo(parts[:idx])
		if err != nil {
			return route{}, err
		}
		if parts[idx+1] == "uploads" {
			if idx+2 == len(parts) || (idx+2 == len(parts)-1 && parts[idx+2] == "") {
				if r.Method != http.MethodPost {
					return route{}, errors.New("unsupported upload start method")
				}
				rt := route{kind: routeUploadStart, repo: repo, access: []Access{{Action: ActionPush, Repo: repo}}}
				mount, from := r.URL.Query().Get("mount"), r.URL.Query().Get("from")
				if mount != "" || from != "" {
					if mount == "" || from == "" {
						return route{}, errors.New("mount and from must be provided together")
					}
					fromRepo, err := canonicalRepo(strings.Split(from, "/"))
					if err != nil {
						return route{}, err
					}
					rt.mount = true
					rt.from = fromRepo
					rt.access = append(rt.access, Access{Action: ActionPull, Repo: fromRepo})
				}
				return rt, nil
			}
			if idx+2 < len(parts) {
				if r.Method != http.MethodPatch && r.Method != http.MethodPut && r.Method != http.MethodGet {
					return route{}, errors.New("unsupported upload session method")
				}
				return route{
					kind:    routeUploadSession,
					repo:    repo,
					session: parts[idx+2],
					access:  []Access{{Action: ActionPush, Repo: repo}},
				}, nil
			}
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodDelete {
			return route{}, errors.New("unsupported blob method")
		}
		action := ActionPull
		if r.Method == http.MethodDelete {
			action = ActionPush
		}
		return route{kind: routeBlob, repo: repo, ref: strings.Join(parts[idx+1:], "/"), access: []Access{{Action: action, Repo: repo}}}, nil
	}

	return route{}, errors.New("unknown OCI route")
}

func lastIndexMarker(parts []string, marker string) int {
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == marker {
			return i
		}
	}
	return -1
}

func canonicalRepo(parts []string) (string, error) {
	if len(parts) == 0 {
		return "", errors.New("empty repository")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("invalid repository path")
		}
		if !repoComponentRE.MatchString(part) {
			return "", errors.New("invalid repository component")
		}
	}
	return strings.Join(parts, "/"), nil
}

func routePath(repo string, suffix ...string) string {
	parts := append([]string{"", "v2"}, strings.Split(repo, "/")...)
	parts = append(parts, suffix...)
	return strings.Join(parts, "/")
}
