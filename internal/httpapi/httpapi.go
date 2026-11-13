// Package httpapi implements the closed, read-only banwords HTTP contract.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/modaniru/danilka-say-patch/internal/auth"
	"github.com/modaniru/danilka-say-patch/internal/catalog"
)

const (
	CatalogPath      = "/api/banwords/catalog"
	DictionaryPath   = "/api/banwords/dictionaries/{id}"
	OpenAPIPath      = "/api/banwords/openapi.json"
	DocsPath         = "/api/banwords/docs"
	HealthPath       = "/healthz"
	dictionaryPrefix = "/api/banwords/dictionaries/"
)

// Routes enumerates exactly the operations documented in openapi.json.
var Routes = [...]string{CatalogPath, DictionaryPath, OpenAPIPath, DocsPath, HealthPath}

type Catalog interface {
	Lookup(string) []catalog.Dictionary
}
type Verifier interface {
	Verify(context.Context, string) (auth.Claims, error)
}

type Options struct {
	Catalog  Catalog
	Current  json.RawMessage
	Verifier Verifier
	OpenAPI  []byte
	Limiter  *RateLimiter
	Logger   *slog.Logger
}

type handler struct{ opts Options }

func New(opts Options) http.Handler {
	if opts.Limiter == nil {
		opts.Limiter = NewRateLimiter(LimiterOptions{})
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	// Snapshot caller-owned byte slices so later mutations cannot alter responses.
	opts.Current = append(json.RawMessage(nil), opts.Current...)
	opts.OpenAPI = append([]byte(nil), opts.OpenAPI...)
	return &handler{opts: opts}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if recover() != nil {
			h.internalError(w)
		}
	}()
	h.serve(w, r)
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	// Match the escaped path: %2F within an id is malformed input (400), not
	// another route. This preserves the existing JavaScript server's URL behavior.
	path := r.URL.EscapedPath()
	id, dictionary := strings.CutPrefix(path, dictionaryPrefix)
	dictionary = dictionary && id != "" && !strings.Contains(id, "/")
	if path == HealthPath {
		if !allowGET(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !dictionary && path != CatalogPath && path != OpenAPIPath && path != DocsPath {
		writeError(w, http.StatusNotFound, "не найдено")
		return
	}
	headers := r.Header.Values("X-Auth-Token")
	if len(headers) != 1 || headers[0] == "" {
		writeError(w, http.StatusNotFound, "не найдено")
		return
	}
	user, err := h.opts.Verifier.Verify(r.Context(), headers[0])
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidToken):
			writeError(w, http.StatusNotFound, "не найдено")
		case errors.Is(err, auth.ErrJWKSUnavailable):
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "авторизация временно недоступна")
		default:
			h.internalError(w)
		}
		return
	}
	if retry := h.opts.Limiter.Take(user.Subject); retry != 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeError(w, http.StatusTooManyRequests, "слишком много запросов")
		return
	}
	if !allowGET(w, r) {
		return
	}
	if dictionary {
		if !catalog.ValidID(id) {
			writeError(w, http.StatusBadRequest, "некорректный идентификатор словаря")
			return
		}
		dictionaries := h.opts.Catalog.Lookup(id)
		if len(dictionaries) == 0 {
			writeError(w, http.StatusNotFound, "не найдено")
			return
		}
		h.writeJSON(w, struct {
			Protocol     string               `json:"protocol"`
			ID           string               `json:"id"`
			Dictionaries []catalog.Dictionary `json:"dictionaries"`
		}{"sp/1", id, dictionaries})
		return
	}
	switch path {
	case CatalogPath:
		h.writeJSON(w, h.opts.Current)
	case OpenAPIPath:
		h.writeJSON(w, json.RawMessage(h.opts.OpenAPI))
	case DocsPath:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(docs))
	}
}

func allowGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return false
	}
	return true
}

func (h *handler) writeJSON(w http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		h.internalError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	data, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{message})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (h *handler) internalError(w http.ResponseWriter) {
	// Errors, panic values, headers, words and subjects may contain secrets.
	h.opts.Logger.Error("request failed")
	writeError(w, http.StatusInternalServerError, "внутренняя ошибка")
}

const docs = `<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Banwords API — OpenAPI</title>
<style>body{font:16px system-ui;max-width:880px;margin:3rem auto;padding:0 1rem;line-height:1.6}code{background:#eee;padding:.2rem}table{border-collapse:collapse}td,th{padding:.6rem;text-align:left;border-bottom:1px solid #ccc}</style>
<h1>Banwords API</h1><p>Спецификация <a href="/api/banwords/openapi.json">OpenAPI 3.1 (Swagger)</a> доступна без внешних ресурсов.</p>
<p>Клиент передаёт <code>Authorization: Bearer bw_…</code> в Caddy. Auth проверяет токен и текущие права владельца, а сервис на Go проверяет внутренний JWT. Нужно право <code>banwords:dictionaries:read</code>.</p>
<table><tr><th>Метод</th><th>Путь</th><th>Ответ</th></tr>
<tr><td>GET</td><td><a href="/api/banwords/catalog">/api/banwords/catalog</a></td><td>Текущий каталог saypatch-rules</td></tr>
<tr><td>GET</td><td>/api/banwords/dictionaries/{id}</td><td>Все словари с коротким hash1; коллизия не выбирается автоматически</td></tr>
</table><p>Неизвестный словарь: 404; неверный hash1: 400; лимит: 429; временно недоступный auth: 503. Слова и текст сообщений не передаются в запросе.</p></html>`
