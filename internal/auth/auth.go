// Package auth verifies only the short-lived JWT issued by auth behind Caddy.
// External bw_ secrets are deliberately not accepted by this service.
package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

var (
	ErrInvalidToken    = errors.New("invalid authentication token")
	ErrJWKSUnavailable = errors.New("authentication keys unavailable")
)

const (
	maxJWTBytes    = 8192
	maxJWKSBytes   = 64 << 10
	maxSafeInteger = 9007199254740991
)

type Claims struct {
	Credential  string
	Subject     string
	Issuer      string
	Audience    string
	Permissions []string
	ExpiresAt   int64
}

type Options struct {
	URL             string
	Client          *http.Client
	Now             func() time.Time
	Timeout         time.Duration
	CacheTTL        time.Duration
	RefreshInterval time.Duration
}

type refresh struct {
	done chan struct{}
	err  error
}

type Verifier struct {
	url                                string
	client                             *http.Client
	now                                func() time.Time
	timeout, cacheTTL, refreshInterval time.Duration
	mu                                 sync.Mutex
	keys                               map[string]ed25519.PublicKey
	fetchedAt, attemptAt               time.Time
	fetched, attempted                 bool
	pending                            *refresh
}

func New(opts Options) *Verifier {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = 300 * time.Second
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 5 * time.Second
	}
	client := http.Client{}
	if opts.Client != nil {
		client = *opts.Client
	}
	// A caller-supplied transport must not relax the timeout or redirect policy.
	client.Timeout = opts.Timeout
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &Verifier{url: opts.URL, client: &client, now: opts.Now, timeout: opts.Timeout,
		cacheTTL: opts.CacheTTL, refreshInterval: opts.RefreshInterval, keys: make(map[string]ed25519.PublicKey)}
}

func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if len(raw) > maxJWTBytes {
		return Claims{}, ErrInvalidToken
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidToken
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		value, ok := decodeBase64(part)
		if !ok {
			return Claims{}, ErrInvalidToken
		}
		decoded[i] = value
	}
	header, ok := object(decoded[0])
	if !ok {
		return Claims{}, ErrInvalidToken
	}
	claims, ok := object(decoded[1])
	if !ok {
		return Claims{}, ErrInvalidToken
	}
	alg, _ := stringValue(header["alg"])
	kid, kidOK := stringValue(header["kid"])
	if alg != "EdDSA" || !kidOK || kid == "" || stringLength(kid) > 128 {
		return Claims{}, ErrInvalidToken
	}
	if typ, exists := header["typ"]; exists {
		value, valid := stringValue(typ)
		if !valid || value != "JWT" {
			return Claims{}, ErrInvalidToken
		}
	}
	key, fresh := v.key(kid)
	if key == nil || !fresh {
		if err := v.ensureKeys(ctx); err != nil {
			return Claims{}, err
		}
		key, fresh = v.key(kid)
	}
	if !fresh {
		return Claims{}, ErrJWKSUnavailable
	}
	if key == nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), decoded[2]) {
		return Claims{}, ErrInvalidToken
	}
	verified, valid := validClaims(claims, v.now())
	if !valid {
		return Claims{}, ErrInvalidToken
	}
	return verified, nil
}

func (v *Verifier) key(kid string) (ed25519.PublicKey, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.keys[kid], v.fetched && v.now().Sub(v.fetchedAt) < v.cacheTTL
}

// A refresh belongs to the verifier, not its first caller. A cancelled waiter
// leaves a bounded shared fetch running so that other requests can use it.
func (v *Verifier) ensureKeys(ctx context.Context) error {
	v.mu.Lock()
	operation := v.pending
	if operation == nil {
		if v.attempted && v.now().Sub(v.attemptAt) < v.refreshInterval {
			v.mu.Unlock()
			return nil
		}
		operation = &refresh{done: make(chan struct{})}
		v.pending = operation
		v.attemptAt, v.attempted = v.now(), true
		go v.refresh(operation)
	}
	v.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-operation.done:
		return operation.err
	}
}

func (v *Verifier) refresh(operation *refresh) {
	keys, err := v.fetchKeys()
	v.mu.Lock()
	defer v.mu.Unlock()
	if err == nil {
		v.keys = keys
		v.fetchedAt, v.fetched = v.now(), true
	}
	operation.err = err
	v.pending = nil
	close(operation.done)
}

func (v *Verifier) fetchKeys() (map[string]ed25519.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	if err != nil {
		return nil, ErrJWKSUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return nil, ErrJWKSUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > maxJWKSBytes {
		return nil, ErrJWKSUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(raw) > maxJWKSBytes {
		return nil, ErrJWKSUnavailable
	}
	return parseKeys(raw)
}

func parseKeys(raw []byte) (map[string]ed25519.PublicKey, error) {
	document, ok := object(raw)
	if !ok {
		return nil, ErrJWKSUnavailable
	}
	var items []json.RawMessage
	if json.Unmarshal(document["keys"], &items) != nil || len(items) == 0 || len(items) > 16 {
		return nil, ErrJWKSUnavailable
	}
	keys := make(map[string]ed25519.PublicKey, len(items))
	for _, item := range items {
		key, ok := object(item)
		if !ok {
			return nil, ErrJWKSUnavailable
		}
		kty, _ := stringValue(key["kty"])
		curve, _ := stringValue(key["crv"])
		kid, validKid := stringValue(key["kid"])
		x, _ := stringValue(key["x"])
		public, validPublic := decodeBase64(x)
		if kty != "OKP" || curve != "Ed25519" || !validKid || kid == "" || stringLength(kid) > 128 || !validPublic || len(public) != ed25519.PublicKeySize {
			return nil, ErrJWKSUnavailable
		}
		if _, private := key["d"]; private {
			return nil, ErrJWKSUnavailable
		}
		for field, expected := range map[string]string{"alg": "EdDSA", "use": "sig"} {
			if raw, exists := key[field]; exists {
				value, valid := stringValue(raw)
				if !valid || value != expected {
					return nil, ErrJWKSUnavailable
				}
			}
		}
		if _, duplicate := keys[kid]; duplicate {
			return nil, ErrJWKSUnavailable
		}
		keys[kid] = ed25519.PublicKey(public)
	}
	return keys, nil
}

func validClaims(raw map[string]json.RawMessage, now time.Time) (Claims, bool) {
	issuer, _ := stringValue(raw["iss"])
	audience, _ := stringValue(raw["aud"])
	subject, _ := stringValue(raw["sub"])
	expires, ok := integer(raw["exp"])
	current := float64(now.Unix()) + float64(now.Nanosecond())/1e9
	if issuer != "danysik-auth" || audience != "banwords" || subject == "" || stringLength(subject) > 128 || !ok || float64(expires) <= current {
		return Claims{}, false
	}
	for field, tolerance := range map[string]float64{"nbf": 0, "iat": 5} {
		if value, exists := raw[field]; exists {
			seconds, valid := integer(value)
			if !valid || float64(seconds) > current+tolerance {
				return Claims{}, false
			}
		}
	}
	credential := ""
	if value, exists := raw["credential"]; exists {
		var valid bool
		credential, valid = stringValue(value)
		if !valid || credential != "service-token" {
			return Claims{}, false
		}
	}
	var permissions []json.RawMessage
	if json.Unmarshal(raw["perms"], &permissions) != nil || len(permissions) > 128 {
		return Claims{}, false
	}
	result := Claims{Credential: credential, Subject: subject, Issuer: issuer, Audience: audience, ExpiresAt: expires, Permissions: make([]string, 0, len(permissions))}
	allowed := false
	for _, rawPermission := range permissions {
		permission, valid := stringValue(rawPermission)
		if !valid || stringLength(permission) > 128 {
			return Claims{}, false
		}
		if permission == "banwords:dictionaries:read" || permission == "superadmin" {
			allowed = true
		}
		result.Permissions = append(result.Permissions, permission)
	}
	return result, allowed
}

func object(raw []byte) (map[string]json.RawMessage, bool) {
	var result map[string]json.RawMessage
	err := json.Unmarshal(raw, &result)
	return result, err == nil && result != nil
}

func stringValue(raw []byte) (string, bool) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	result, ok := value.(string)
	return result, ok
}

func integer(raw []byte) (int64, bool) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return 0, false
	}
	number, ok := value.(float64)
	if !ok || math.Abs(number) > maxSafeInteger || math.Trunc(number) != number {
		return 0, false
	}
	return int64(number), true
}

func decodeBase64(raw string) ([]byte, bool) {
	if raw == "" {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, false
	}
	return decoded, true
}

func stringLength(value string) int {
	result := 0
	for _, r := range value {
		result += utf16.RuneLen(r)
	}
	return result
}
