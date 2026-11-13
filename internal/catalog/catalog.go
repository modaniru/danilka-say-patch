// Package catalog loads the single Git-managed functional rules catalog.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxFileBytes = 64 * 1024

var sourceWord = regexp.MustCompile(`^[\p{L}\p{M}\p{N}_]+$`)

// Catalog snapshots deterministic response bytes and their complete SHA-256.
// The hash includes every functional field, rule order and replacement pool.
type Catalog struct {
	body []byte
	hash string
}

// Body returns a copy so callers cannot mutate the loaded catalog.
func (c *Catalog) Body() []byte { return slices.Clone(c.body) }
func (c *Catalog) Hash() string { return c.hash }

func readJSON(fsys fs.FS) ([]byte, error) {
	file, err := fsys.Open("catalog.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFileBytes {
		return nil, errors.New("catalog file too large")
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, errors.New("invalid catalog JSON")
	}
	return raw, nil
}

// onlyFields applies the public schema without knowledge of client-specific flags.
func onlyFields(value map[string]any, names ...string) bool {
	for name := range value {
		if !slices.Contains(names, name) {
			return false
		}
	}
	return true
}

// jsWhitespace matches String.trim used by the extension's rule validation.
func jsWhitespace(c rune) bool {
	return c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == ' ' ||
		c == '\u00a0' || c == '\u1680' || c >= '\u2000' && c <= '\u200a' ||
		c == '\u2028' || c == '\u2029' || c == '\u202f' || c == '\u205f' || c == '\u3000' || c == '\ufeff'
}

func validate(value map[string]any) error {
	variants, ok := value["variants"].([]any)
	if !onlyFields(value, "format", "version", "variants", "rules") || value["format"] != "saypatch-rules" || value["version"] != float64(1) ||
		!ok || len(variants) == 0 || len(variants) > 2500 {
		return errors.New("invalid catalog")
	}
	for _, entry := range variants {
		variant, ok := entry.(string)
		if !ok || strings.TrimFunc(variant, jsWhitespace) == "" || len(utf16.Encode([]rune(variant))) > 100 {
			return errors.New("invalid catalog")
		}
	}
	rules, ok := value["rules"].([]any)
	if !ok || len(rules) == 0 || len(rules) > 50 {
		return errors.New("invalid catalog")
	}
	for _, entry := range rules {
		rule, ok := entry.(map[string]any)
		if !ok || !onlyFields(rule, "word", "category", "variantIds", "matchMode", "replaceMode") {
			return errors.New("invalid rule")
		}
		word, wordOK := rule["word"].(string)
		category, categoryOK := rule["category"].(string)
		ids, idsOK := rule["variantIds"].([]any)
		// UTF-16 lengths are format bounds shared with the JS client; words
		// are neither normalized nor lowercased or hashed separately here.
		if !wordOK || !sourceWord.MatchString(word) || len(utf16.Encode([]rune(word))) > 50 ||
			!categoryOK || category != "safe" && category != "banword" || !idsOK || len(ids) == 0 || len(ids) > 50 {
			return errors.New("invalid rule")
		}
		for _, entry := range ids {
			id, ok := entry.(float64)
			if !ok || math.Trunc(id) != id || id < 0 || id >= float64(len(variants)) {
				return errors.New("invalid rule")
			}
		}
		for field, accepted := range map[string][]string{"matchMode": {"word", "substring"}, "replaceMode": {"word", "match"}} {
			mode, ok := rule[field].(string)
			if !ok || !slices.Contains(accepted, mode) {
				return errors.New("explicit functional modes required")
			}
		}
	}
	return nil
}

// Load reads only catalog.json from the supplied root. JSON object keys are
// sorted by json.Marshal; formatting and key order do not affect freshness.
func Load(fsys fs.FS) (*Catalog, error) {
	raw, err := readJSON(fsys)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, errors.New("invalid catalog")
	}
	if err := validate(value); err != nil {
		return nil, err
	}
	// JSON decoding and validation leave only finite JSON values, so Marshal
	// cannot fail. These exact bytes are served without another JSON encoding.
	body, _ := json.Marshal(value)
	if len(body) > MaxFileBytes {
		return nil, errors.New("catalog response too large")
	}
	sum := sha256.Sum256(body)
	return &Catalog{body: body, hash: hex.EncodeToString(sum[:])}, nil
}
