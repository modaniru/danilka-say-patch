// Package catalog loads immutable, versioned sp/1 dictionaries.
package catalog

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

const MaxFileBytes = 64 * 1024

var versionPattern = regexp.MustCompile(`^v[1-9][0-9]{0,5}$`)

// Dictionary retains both the short lookup ID and the complete content digest.
// Distinct dictionaries may have the same ID and must all be returned.
type Dictionary struct {
	ID     string   `json:"id"`
	Digest string   `json:"digest"`
	Words  []string `json:"words"`
}

type Catalog struct {
	Current json.RawMessage
	index   map[string][]Dictionary
}

// ValidID accepts exactly four ASCII Base64url characters without padding.
func ValidID(id string) bool {
	if len(id) != 4 {
		return false
	}
	for _, c := range id {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func inRanges(c rune, intervals [][2]rune) bool {
	index := sort.Search(len(intervals), func(i int) bool { return intervals[i][1] >= c })
	return index < len(intervals) && intervals[index][0] <= c
}

func validWord(word string) bool {
	if word == "" || !utf8.ValidString(word) || len(utf16.Encode([]rune(word))) > 100 {
		return false
	}
	for _, c := range word {
		if !inRanges(c, wordRanges[:]) {
			return false
		}
	}
	return true
}

// A Caser is stateful, so each call owns its instance. Unicode full lowercase
// expands dotted I; the versioned Final_Sigma context is handled explicitly.
// x/text uses newer Cased properties and treats U+0345 differently from JS.
func canonicalWord(word string) string {
	word = norm.NFC.String(word)
	lower := cases.Lower(language.Und)
	if !strings.ContainsRune(word, 'Σ') {
		return norm.NFC.String(lower.String(word))
	}
	runes := []rune(word)
	var result strings.Builder
	result.Grow(len(word))
	for i, c := range runes {
		if c == 'Σ' {
			if finalSigma(runes, i) {
				result.WriteRune('ς')
			} else {
				result.WriteRune('σ')
			}
		} else {
			result.WriteString(lower.String(string(c)))
		}
	}
	return norm.NFC.String(result.String())
}

// Final_Sigma ignores Case_Ignorable first, including characters that are also
// Cased (e.g. U+0345). Use JS Unicode16 properties, not the Go toolchain's version.
func finalSigma(word []rune, index int) bool {
	preceded := false
	for i := index - 1; i >= 0; i-- {
		if inRanges(word[i], caseIgnorableRanges[:]) {
			continue
		}
		preceded = inRanges(word[i], casedRanges[:])
		break
	}
	if !preceded {
		return false
	}
	for i := index + 1; i < len(word); i++ {
		if inRanges(word[i], caseIgnorableRanges[:]) {
			continue
		}
		return !inRanges(word[i], casedRanges[:])
	}
	return true
}

// PrepareDictionary implements the extension's exact sp/1 wire format:
// NFC -> Unicode full lowercase -> NFC -> deduplicate -> UTF-16 sort.
func PrepareDictionary(input []string) (Dictionary, error) {
	if len(input) == 0 || len(input) > 50 {
		return Dictionary{}, errors.New("invalid dictionary")
	}
	words := make([]string, 0, len(input))
	seen := make(map[string]bool, len(input))
	for _, word := range input {
		if !validWord(word) {
			return Dictionary{}, errors.New("invalid dictionary")
		}
		word = canonicalWord(word)
		if !seen[word] {
			words = append(words, word)
			seen[word] = true
		}
	}
	slices.SortFunc(words, func(a, b string) int {
		return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
	})
	// Words have already been restricted to L/M/N/_. None can contain JSON
	// syntax, controls, HTML metacharacters or U+2028/U+2029. Marshal therefore
	// matches JSON.stringify byte-for-byte and cannot return an encoding error.
	canonical, _ := json.Marshal([]any{"sp", 1, "dictionary", words})
	hash := sha256.Sum256(canonical)
	return Dictionary{
		ID:     base64.RawURLEncoding.EncodeToString(hash[:3]),
		Digest: hex.EncodeToString(hash[:]),
		Words:  words,
	}, nil
}

func readJSON(fsys fs.FS, name string) ([]byte, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFileBytes {
		return nil, errors.New("seed file too large")
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, errors.New("invalid seed JSON")
	}
	return raw, nil
}

// jsWhitespace follows ECMAScript String.trim rather than Go TrimSpace:
// ECMAScript includes BOM and excludes the NEL control character U+0085.
func jsWhitespace(c rune) bool {
	return c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == ' ' ||
		c == '\u00a0' || c == '\u1680' || c >= '\u2000' && c <= '\u200a' ||
		c == '\u2028' || c == '\u2029' || c == '\u202f' || c == '\u205f' || c == '\u3000' || c == '\ufeff'
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

func validateCatalog(raw []byte, complete bool) (Dictionary, error) {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return Dictionary{}, errors.New("invalid catalog")
	}
	if !onlyFields(value, "format", "version", "variants", "rules") {
		return Dictionary{}, errors.New("invalid catalog")
	}
	variants, ok := value["variants"].([]any)
	if value["format"] != "saypatch-rules" || value["version"] != float64(1) || !ok || len(variants) == 0 || len(variants) > 2500 {
		return Dictionary{}, errors.New("invalid catalog")
	}
	for _, entry := range variants {
		variant, ok := entry.(string)
		if !ok || strings.TrimFunc(variant, jsWhitespace) == "" || len(utf16.Encode([]rune(variant))) > 100 {
			return Dictionary{}, errors.New("invalid catalog")
		}
	}
	rules, ok := value["rules"].([]any)
	if !ok || len(rules) == 0 || len(rules) > 50 {
		return Dictionary{}, errors.New("invalid catalog")
	}
	words := make([]string, 0, len(rules))
	for _, entry := range rules {
		rule, ok := entry.(map[string]any)
		if !ok || !onlyFields(rule, "word", "category", "variantIds", "matchMode", "replaceMode") {
			return Dictionary{}, errors.New("invalid rule")
		}
		word, wordOK := rule["word"].(string)
		category, categoryOK := rule["category"].(string)
		ids, idsOK := rule["variantIds"].([]any)
		if !wordOK || len(utf16.Encode([]rune(word))) > 50 || !categoryOK || category != "safe" && category != "banword" ||
			!idsOK || len(ids) == 0 || len(ids) > 50 {
			return Dictionary{}, errors.New("invalid rule")
		}
		for _, entry := range ids {
			id, ok := entry.(float64)
			if !ok || math.Trunc(id) != id || id < 0 || id >= float64(len(variants)) {
				return Dictionary{}, errors.New("invalid rule")
			}
		}
		for field, accepted := range map[string][]string{"matchMode": {"word", "substring"}, "replaceMode": {"word", "match"}} {
			entry, exists := rule[field]
			if !exists {
				if complete {
					return Dictionary{}, errors.New("current catalog requires explicit rule modes")
				}
				continue
			}
			mode, ok := entry.(string)
			if !ok || !slices.Contains(accepted, mode) {
				return Dictionary{}, errors.New("invalid rule")
			}
		}
		words = append(words, word)
	}
	return PrepareDictionary(words)
}

func cloneDictionary(value Dictionary) Dictionary {
	value.Words = slices.Clone(value.Words)
	return value
}

func indexDictionaries(dictionaries []Dictionary) (map[string][]Dictionary, error) {
	index := make(map[string][]Dictionary)
	for _, dictionary := range dictionaries {
		matches := index[dictionary.ID]
		duplicate := slices.ContainsFunc(matches, func(existing Dictionary) bool { return existing.Digest == dictionary.Digest })
		if duplicate {
			continue
		}
		if len(matches) >= 8 {
			return nil, errors.New("too many dictionaries with the same id")
		}
		index[dictionary.ID] = append(matches, cloneDictionary(dictionary))
	}
	return index, nil
}

// Load reads all published versions before serving requests. The FS must be
// rooted at data/, containing manifest.json and versions/vN.json. Every current
// rule must declare its functional modes; legacy optional modes remain readable
// only in historical versions.
func Load(fsys fs.FS) (*Catalog, error) {
	raw, err := readJSON(fsys, "manifest.json")
	if err != nil {
		return nil, err
	}
	// Match JavaScript's case-sensitive property lookup. Unmarshal into a
	// struct would also accept Current/Versions aliases and change the wire contract.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, errors.New("invalid manifest")
	}
	var manifest struct {
		Current  string
		Versions []string
	}
	currentErr := json.Unmarshal(fields["current"], &manifest.Current)
	versionsErr := json.Unmarshal(fields["versions"], &manifest.Versions)
	if currentErr != nil || versionsErr != nil || len(manifest.Versions) == 0 || len(manifest.Versions) > 64 {
		return nil, errors.New("invalid manifest")
	}
	versions := make(map[string]bool, len(manifest.Versions))
	for _, version := range manifest.Versions {
		if !versionPattern.MatchString(version) || versions[version] {
			return nil, errors.New("invalid manifest")
		}
		versions[version] = true
	}
	if !versions[manifest.Current] {
		return nil, errors.New("invalid manifest")
	}
	catalog := &Catalog{}
	dictionaries := make([]Dictionary, 0, len(manifest.Versions))
	for _, version := range manifest.Versions {
		raw, err := readJSON(fsys, "versions/"+version+".json")
		if err != nil {
			return nil, err
		}
		dictionary, err := validateCatalog(raw, version == manifest.Current)
		if err != nil {
			return nil, fmt.Errorf("invalid catalog %s: %w", version, err)
		}
		dictionaries = append(dictionaries, dictionary)
		if version == manifest.Current {
			catalog.Current = slices.Clone(raw)
		}
	}
	catalog.index, err = indexDictionaries(dictionaries)
	if err != nil {
		return nil, err
	}
	return catalog, nil
}

// Lookup returns copies so a caller cannot mutate future answers.
func (c *Catalog) Lookup(id string) []Dictionary {
	matches := c.index[id]
	result := make([]Dictionary, 0, len(matches))
	for _, match := range matches {
		result = append(result, cloneDictionary(match))
	}
	return result
}
