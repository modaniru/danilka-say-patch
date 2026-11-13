package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modaniru/danilka-say-patch/internal/auth"
	"github.com/modaniru/danilka-say-patch/internal/catalog"
)

type verifierFunc func(context.Context, string) (auth.Claims, error)

func (f verifierFunc) Verify(ctx context.Context, raw string) (auth.Claims, error) {
	return f(ctx, raw)
}

type fakeCatalog struct {
	dictionaries []catalog.Dictionary
	fail         bool
}

func (c fakeCatalog) Lookup(id string) []catalog.Dictionary {
	if c.fail {
		panic("private catalog material")
	}
	if id == "0dMf" || id == "abcd" {
		return c.dictionaries
	}
	return nil
}
func setup(t *testing.T) Options {
	t.Helper()
	current, err := os.ReadFile("../../data/versions/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	specification, err := os.ReadFile("../../openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var seed struct {
		Rules []struct {
			Word string `json:"word"`
		} `json:"rules"`
	}
	if err = json.Unmarshal(current, &seed); err != nil {
		t.Fatal(err)
	}
	words := make([]string, len(seed.Rules))
	for i, rule := range seed.Rules {
		words[i] = rule.Word
	}
	dictionary, err := catalog.PrepareDictionary(words)
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Catalog: fakeCatalog{dictionaries: []catalog.Dictionary{dictionary}}, Current: current, OpenAPI: specification,
		Verifier: verifierFunc(func(ctx context.Context, raw string) (auth.Claims, error) {
			if raw != "valid" {
				return auth.Claims{}, auth.ErrInvalidToken
			}
			return auth.Claims{Subject: "123"}, nil
		}),
	}
}
func request(h http.Handler, method, path string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for _, value := range headers {
		r.Header.Add("X-Auth-Token", value)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func decode(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestHTTPContractAndOpenAPI(t *testing.T) {
	opts := setup(t)
	h := New(opts)
	for _, path := range []string{CatalogPath, "/api/banwords/dictionaries/0dMf", OpenAPIPath, DocsPath} {
		w := request(h, "GET", path, "valid")
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing security headers")
		}
		if path == DocsPath {
			if w.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
				t.Fatal("documentation headers")
			}
			if !strings.Contains(w.Body.String(), OpenAPIPath) || strings.Contains(w.Body.String(), "https://") || strings.Contains(w.Body.String(), "<script") {
				t.Fatal("documentation must remain offline")
			}
		} else if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatal("JSON content type")
		}
	}
	if got := decode(t, request(h, "GET", CatalogPath, "valid").Body.Bytes()); !reflect.DeepEqual(got, decode(t, opts.Current)) {
		t.Fatal("catalog changed")
	}
	if got := decode(t, request(h, "GET", OpenAPIPath, "valid").Body.Bytes()); !reflect.DeepEqual(got, decode(t, opts.OpenAPI)) {
		t.Fatal("spec changed")
	}
	dictionary := request(h, "GET", "/api/banwords/dictionaries/0dMf?message=never-used", "valid")
	var found struct {
		Protocol     string               `json:"protocol"`
		ID           string               `json:"id"`
		Dictionaries []catalog.Dictionary `json:"dictionaries"`
	}
	if err := json.Unmarshal(dictionary.Body.Bytes(), &found); err != nil {
		t.Fatal(err)
	}
	if found.Protocol != "sp/1" || found.ID != "0dMf" || len(found.Dictionaries) != 1 || len(found.Dictionaries[0].Words) != 22 {
		t.Fatalf("lookup: %+v", found)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]json.RawMessage `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(opts.OpenAPI, &spec); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(spec.Paths))
	for path, methods := range spec.Paths {
		paths = append(paths, path)
		if len(methods) != 1 {
			t.Fatal("only GET is documented")
		}
		operation, ok := methods["get"]
		if !ok {
			t.Fatal("missing GET")
		}
		required := []string{"405"}
		if path == HealthPath {
			required = append(required, "204")
		} else {
			required = append(required, "200", "404", "429", "500", "503")
		}
		if path == DictionaryPath {
			required = append(required, "400")
		}
		for _, status := range required {
			if _, ok := operation.Responses[status]; !ok {
				t.Fatalf("%s missing %s", path, status)
			}
		}
	}
	expected := slices.Clone(Routes[:])
	slices.Sort(paths)
	slices.Sort(expected)
	if !reflect.DeepEqual(paths, expected) {
		t.Fatalf("OpenAPI routes %v != handlers %v", paths, expected)
	}
}

func TestAuthenticationAndSenderHeaders(t *testing.T) {
	opts := setup(t)
	h := New(opts)
	for _, path := range []string{CatalogPath, OpenAPIPath, DocsPath, "/api/banwords/dictionaries/0dMf"} {
		for _, headers := range [][]string{nil, {""}, {"garbage"}, {"valid", "valid"}, {"valid", ""}} {
			w := request(h, "GET", path, headers...)
			if w.Code != 404 || w.Body.String() != `{"error":"не найдено"}` {
				t.Fatalf("%s %q: %d %s", path, headers, w.Code, w.Body)
			}
		}
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer bw_private")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("external bearer accepted")
		}
	}
	// Request cancellation/deadlines must reach the verifier unchanged.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts.Verifier = verifierFunc(func(got context.Context, _ string) (auth.Claims, error) {
		if got != ctx {
			t.Fatal("context replaced")
		}
		return auth.Claims{}, auth.ErrInvalidToken
	})
	h = New(opts)
	r := httptest.NewRequest("GET", CatalogPath, nil).WithContext(ctx)
	r.Header.Set("X-Auth-Token", "valid")
	h.ServeHTTP(httptest.NewRecorder(), r)
}

func TestMethodsHealthAndMalformedRoutes(t *testing.T) {
	opts := setup(t)
	h := New(opts)
	health := request(h, "GET", HealthPath)
	if health.Code != 204 || health.Body.Len() != 0 {
		t.Fatalf("health: %d %s", health.Code, health.Body)
	}
	for _, path := range []string{HealthPath, CatalogPath, OpenAPIPath, DocsPath, "/api/banwords/dictionaries/0dMf"} {
		for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS", "HEAD"} {
			w := request(h, method, path, "valid")
			if w.Code != 405 || w.Header().Get("Allow") != "GET" {
				t.Fatalf("%s %s: %d", method, path, w.Code)
			}
		}
	}
	// Unsupported methods on closed routes must not reveal them before auth.
	if got := request(h, "POST", CatalogPath).Code; got != 404 {
		t.Fatalf("auth must precede 405, got %d", got)
	}
	for _, id := range []string{"abc", "abcde", "a%2Fb", "%0Aabc", "abcd=", "%30dMf", "%E2%82%AC"} {
		w := request(h, "GET", "/api/banwords/dictionaries/"+id, "valid")
		if w.Code != 400 {
			t.Fatalf("id %s: %d", id, w.Code)
		}
	}
	for _, path := range []string{"/missing", "/api/banwords/dictionaries/", "/api/banwords/dictionaries/0dMf/extra", CatalogPath + "/", CatalogPath + "%2F"} {
		if got := request(h, "GET", path).Code; got != 404 {
			t.Fatalf("path %s: %d", path, got)
		}
	}
	if got := request(h, "GET", "/api/banwords/dictionaries/zzzz", "valid").Code; got != 404 {
		t.Fatalf("unknown id: %d", got)
	}
}

func TestLookupReturnsEveryCollision(t *testing.T) {
	opts := setup(t)
	opts.Catalog = fakeCatalog{dictionaries: []catalog.Dictionary{{ID: "abcd", Digest: "first", Words: []string{"a"}}, {ID: "abcd", Digest: "second", Words: []string{"b"}}}}
	w := request(New(opts), "GET", "/api/banwords/dictionaries/abcd", "valid")
	var found struct {
		Dictionaries []catalog.Dictionary `json:"dictionaries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &found); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(found.Dictionaries) != 2 || found.Dictionaries[0].Digest == found.Dictionaries[1].Digest {
		t.Fatalf("collision response %d %+v", w.Code, found)
	}
}

func TestErrorsAndPanicsNeverExposeSecrets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{{"invalid", fmt.Errorf("private: %w", auth.ErrInvalidToken), 404}, {"keys", fmt.Errorf("private: %w", auth.ErrJWKSUnavailable), 503}, {"unknown", errors.New("private token value"), 500}} {
		t.Run(tc.name, func(t *testing.T) {
			opts := setup(t)
			var logs bytes.Buffer
			opts.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
			opts.Verifier = verifierFunc(func(context.Context, string) (auth.Claims, error) { return auth.Claims{}, tc.err })
			w := request(New(opts), "GET", CatalogPath, "valid")
			if w.Code != tc.status {
				t.Fatalf("got %d", w.Code)
			}
			if tc.status == 503 && w.Header().Get("Retry-After") != "5" {
				t.Fatal("retry header")
			}
			if strings.Contains(w.Body.String(), "private") || strings.Contains(logs.String(), "private") {
				t.Fatal("secret exposed")
			}
			if (logs.Len() > 0) != (tc.status == 500) {
				t.Fatal("unexpected error logging")
			}
		})
	}
	for _, kind := range []string{"verifier", "catalog", "bad current", "bad openapi"} {
		t.Run(kind, func(t *testing.T) {
			opts := setup(t)
			var logs bytes.Buffer
			opts.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
			path := CatalogPath
			switch kind {
			case "verifier":
				opts.Verifier = verifierFunc(func(context.Context, string) (auth.Claims, error) { panic("private bearer") })
			case "catalog":
				opts.Catalog = fakeCatalog{fail: true}
				path = "/api/banwords/dictionaries/0dMf"
			case "bad current":
				opts.Current = json.RawMessage("private broken JSON")
			case "bad openapi":
				opts.OpenAPI = []byte("private broken JSON")
				path = OpenAPIPath
			}
			w := request(New(opts), "GET", path, "valid")
			if w.Code != 500 || w.Body.String() != `{"error":"внутренняя ошибка"}` {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if !strings.Contains(logs.String(), "request failed") || strings.Contains(logs.String(), "private") {
				t.Fatal("unsafe logs")
			}
		})
	}
}

func TestSnapshotInputsAndHTTPServer(t *testing.T) {
	opts := setup(t)
	h := New(opts)
	before := request(h, "GET", CatalogPath, "valid").Body.String()
	spec := request(h, "GET", OpenAPIPath, "valid").Body.String()
	for i := range opts.Current {
		opts.Current[i] = 'x'
	}
	for i := range opts.OpenAPI {
		opts.OpenAPI[i] = 'x'
	}
	if request(h, "GET", CatalogPath, "valid").Body.String() != before || request(h, "GET", OpenAPIPath, "valid").Body.String() != spec {
		t.Fatal("caller mutated snapshot")
	}
	server := httptest.NewServer(h)
	defer server.Close()
	r, err := http.NewRequest("GET", server.URL+CatalogPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Auth-Token", "valid")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || !reflect.DeepEqual(decode(t, data), decode(t, []byte(before))) {
		t.Fatal("wire response")
	}
}

func TestHTTPRateLimit(t *testing.T) {
	opts := setup(t)
	now := time.Unix(1000, 0)
	opts.Limiter = NewRateLimiter(LimiterOptions{Limit: 1, MaxUsers: 2, Now: func() time.Time { return now }})
	opts.Verifier = verifierFunc(func(_ context.Context, raw string) (auth.Claims, error) { return auth.Claims{Subject: raw}, nil })
	h := New(opts)
	if request(h, "GET", CatalogPath, "alice").Code != 200 {
		t.Fatal("first request blocked")
	}
	w := request(h, "GET", DocsPath, "alice")
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("%d %+v", w.Code, w.Header())
	}
	if request(h, "GET", CatalogPath, "bob").Code != 200 || request(h, "GET", CatalogPath, "carol").Code != 429 {
		t.Fatal("subject/memory bounds")
	}
	now = now.Add(time.Minute)
	if request(h, "GET", CatalogPath, "carol").Code != 200 {
		t.Fatal("window did not expire")
	}
}

func TestLimiterWindowBoundsAndDefaults(t *testing.T) {
	now := time.Unix(1, 0)
	l := NewRateLimiter(LimiterOptions{Limit: 1, Period: 1500 * time.Millisecond, MaxUsers: 1, Now: func() time.Time { return now }})
	if l.Take("alice") != 0 || l.Take("alice") != 2 || l.Take("bob") != 2 {
		t.Fatal("bounded fixed window")
	}
	now = now.Add(time.Second)
	if l.Take("alice") != 1 {
		t.Fatal("Retry-After must round up")
	}
	now = now.Add(500 * time.Millisecond)
	if l.Take("alice") != 0 {
		t.Fatal("same subject expiry")
	}
	now = now.Add(1500 * time.Millisecond)
	if l.Take("bob") != 0 || len(l.users) != 1 {
		t.Fatal("expired records not evicted")
	}
	defaults := NewRateLimiter(LimiterOptions{})
	for i := 0; i < 60; i++ {
		if defaults.Take("subject") != 0 {
			t.Fatal("default limit")
		}
	}
	if retry := defaults.Take("subject"); retry < 1 || retry > 60 {
		t.Fatalf("default retry %d", retry)
	}
	if retrySeconds(0) != 1 {
		t.Fatal("minimum retry")
	}
}

func TestLimiterConcurrentRequests(t *testing.T) {
	l := NewRateLimiter(LimiterOptions{Limit: 10})
	var accepted atomic.Int32
	var group sync.WaitGroup
	for range 100 {
		group.Go(func() {
			if l.Take("subject") == 0 {
				accepted.Add(1)
			}
		})
	}
	group.Wait()
	if accepted.Load() != 10 {
		t.Fatalf("accepted %d", accepted.Load())
	}
}

// Exercise the complete service-side path with a real Ed25519 JWT and a local
// JWKS transport; no OAuth or production endpoints are contacted.
func TestSignedJWTThroughHTTPAndJWKS(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	var fetches atomic.Int32
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if r.URL.Path != "/keys" {
			t.Error("incorrect JWKS path")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"first","alg":"EdDSA","use":"sig","x":%q}]}`, base64.RawURLEncoding.EncodeToString(public))
	}))
	defer keys.Close()
	opts := setup(t)
	opts.Verifier = auth.New(auth.Options{URL: keys.URL + "/keys", Now: func() time.Time { return now }, CacheTTL: time.Minute})
	h := New(opts)
	issue := func(audience string, perms []string, expires int64) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"first"}`))
		payload, err := json.Marshal(map[string]any{"iss": "danysik-auth", "sub": "123", "aud": audience, "perms": perms, "iat": 1000, "exp": expires})
		if err != nil {
			t.Fatal(err)
		}
		signing := header + "." + base64.RawURLEncoding.EncodeToString(payload)
		return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signing)))
	}
	token := issue("banwords", []string{"banwords:dictionaries:read"}, 1120)
	if got := request(h, "GET", "/api/banwords/dictionaries/0dMf", token).Code; got != 200 {
		t.Fatalf("valid JWT got %d", got)
	}
	for _, bad := range []string{issue("tts", []string{"banwords:dictionaries:read"}, 1120), issue("banwords", []string{"banwords"}, 1120), issue("banwords", []string{"banwords:dictionaries:read"}, 999)} {
		if got := request(h, "GET", CatalogPath, bad).Code; got != 404 {
			t.Fatalf("invalid claims got %d", got)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("JWKS cache: fetched %d times", fetches.Load())
	}
	keys.Close()
	if got := request(h, "GET", CatalogPath, token).Code; got != 200 {
		t.Fatalf("fresh cached keys got %d", got)
	}
	now = now.Add(61 * time.Second)
	unavailable := request(h, "GET", CatalogPath, token)
	if unavailable.Code != 503 || unavailable.Header().Get("Retry-After") != "5" {
		t.Fatalf("expired JWKS cache got %d", unavailable.Code)
	}
}
