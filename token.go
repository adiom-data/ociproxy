package ociproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type uploadState struct {
	UploadID string `json:"u"`
	Repo     string `json:"r"`
	Upstream string `json:"h,omitempty"`
	Query    string `json:"q,omitempty"`
	Expiry   int64  `json:"exp"`
}

// TokenCodec signs and verifies client-echoed upload session state.
type TokenCodec struct {
	Primary   []byte
	Secondary []byte
	TTL       time.Duration
	Now       func() time.Time
}

func (c TokenCodec) Sign(state uploadState) (string, error) {
	if len(c.Primary) == 0 {
		return "", errors.New("primary token key is required")
	}
	if state.Expiry == 0 {
		ttl := c.TTL
		if ttl == 0 {
			ttl = 30 * time.Minute
		}
		state.Expiry = c.now().Add(ttl).Unix()
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	payload64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(c.Primary, []byte(payload64))
	return payload64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c TokenCodec) Verify(token string) (uploadState, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return uploadState{}, errors.New("invalid upload token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return uploadState{}, errors.New("invalid upload token signature")
	}
	if !c.validSig([]byte(parts[0]), sig) {
		return uploadState{}, errors.New("invalid upload token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return uploadState{}, errors.New("invalid upload token payload")
	}
	var state uploadState
	if err := json.Unmarshal(payload, &state); err != nil {
		return uploadState{}, err
	}
	if state.UploadID == "" || state.Repo == "" || state.Expiry == 0 {
		return uploadState{}, errors.New("incomplete upload token")
	}
	if c.now().Unix() >= state.Expiry {
		return uploadState{}, errors.New("expired upload token")
	}
	return state, nil
}

func (c TokenCodec) validSig(payload, sig []byte) bool {
	if len(c.Primary) > 0 && hmac.Equal(sign(c.Primary, payload), sig) {
		return true
	}
	return len(c.Secondary) > 0 && hmac.Equal(sign(c.Secondary, payload), sig)
}

func (c TokenCodec) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func sign(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil)
}

func extractExpiry(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) == 0 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0
	}
	var raw map[string]any
	if json.Unmarshal(payload, &raw) != nil {
		return 0
	}
	switch exp := raw["exp"].(type) {
	case float64:
		return int64(exp)
	case string:
		v, _ := strconv.ParseInt(exp, 10, 64)
		return v
	default:
		return 0
	}
}
