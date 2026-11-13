package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"unicode/utf8"
)

func encoded(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ruleCatalog(word string) map[string]any {
	return map[string]any{
		"format": "saypatch-rules", "version": 1,
		"variants": []any{"replacement"},
		"rules":    []any{map[string]any{"word": word, "category": "banword", "variantIds": []any{0}, "matchMode": "substring", "replaceMode": "word"}},
	}
}

func catalogFS(t *testing.T, words []string, current string) fstest.MapFS {
	t.Helper()
	files := fstest.MapFS{}
	versions := []string{}
	for i, word := range words {
		version := "v" + strconv.Itoa(i+1)
		versions = append(versions, version)
		files["versions/"+version+".json"] = &fstest.MapFile{Data: encoded(t, ruleCatalog(word))}
	}
	files["manifest.json"] = &fstest.MapFile{Data: encoded(t, map[string]any{"current": current, "versions": versions})}
	return files
}

func prepared(t *testing.T, words ...string) Dictionary {
	t.Helper()
	result, err := PrepareDictionary(words)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestJavaScriptUnicode16Parity(t *testing.T) {
	// Checked-in reference data comes from Node.js 22.18, not from Go's
	// Unicode tables. The generator is test-only; Go CI does not need Node.
	raw, err := os.ReadFile("testdata/js-unicode16.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		Unicode       string
		ContextDigest string
		Changes       [][2]string
		Ranges        [][2]rune
		Dictionaries  []struct {
			Input  []string
			Words  []string
			ID     string
			Digest string
		}
	}
	if err := json.Unmarshal(raw, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.Unicode != "16.0" || len(reference.Changes) != 2521 || len(reference.Ranges) != 820 {
		t.Fatal("reference fixture unexpectedly changed")
	}
	changes := make(map[string]string, len(reference.Changes))
	for _, change := range reference.Changes {
		changes[change[0]] = change[1]
	}
	contexts := sha256.New()
	index := 0
	for cp := rune(0); cp <= utf8.MaxRune; cp++ {
		for index < len(reference.Ranges) && reference.Ranges[index][1] < cp {
			index++
		}
		allowed := index < len(reference.Ranges) && reference.Ranges[index][0] <= cp
		word := string(cp)
		if validWord(word) != allowed {
			t.Fatalf("JavaScript word validation differs at U+%04X", cp)
		}
		if !allowed {
			continue
		}
		expected, changed := changes[word]
		if !changed {
			expected = word
		}
		if got := canonicalWord(word); got != expected {
			t.Fatalf("JavaScript lowercase/NFC differs at U+%04X: got %q, want %q", cp, got, expected)
		}
		for _, context := range []string{"AΣ" + word, word + "Σ", "AΣ" + word + "A", "A" + word + "Σ"} {
			contexts.Write([]byte(canonicalWord(context)))
			contexts.Write([]byte{0})
		}
	}
	if got := hex.EncodeToString(contexts.Sum(nil)); got != reference.ContextDigest {
		t.Fatalf("JavaScript Final_Sigma context differs: got %s, want %s", got, reference.ContextDigest)
	}
	for i, fixture := range reference.Dictionaries {
		got := prepared(t, fixture.Input...)
		expected := Dictionary{ID: fixture.ID, Digest: fixture.Digest, Words: fixture.Words}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("JavaScript dictionary fixture %d differs: got %#v, want %#v", i, got, expected)
		}
	}
}

func TestPrepareDictionaryValidationAndCopy(t *testing.T) {
	for _, input := range [][]string{
		nil, {}, make([]string, 51), {""}, {"a b"}, {"[x]"}, {"a\n"}, {"<script>"},
		{"a\"b"}, {"a\u2028b"}, {"a\u2029b"}, {"\u00ad"}, {"\ufffd"}, {"\U00016ea0"},
		{string([]byte{0xed, 0xa0, 0x80})}, {strings.Repeat("a", 101)}, {strings.Repeat("𐐀", 51)},
	} {
		if _, err := PrepareDictionary(input); err == nil {
			t.Errorf("accepted invalid dictionary %#v", input)
		}
	}
	for _, word := range []string{strings.Repeat("a", 100), strings.Repeat("𐐀", 50)} {
		if _, err := PrepareDictionary([]string{word}); err != nil {
			t.Errorf("rejected allowed UTF-16 length: %v", err)
		}
	}
	input := []string{"É", "a", "E\u0301", "A"}
	got := prepared(t, input...)
	input[0] = "mutated"
	want := prepared(t, "a", "é")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("case normalization/dedup or input isolation failed: %#v", got)
	}
	got.Words[0] = "mutated"
	if prepared(t, "a", "é").Words[0] != "a" {
		t.Fatal("dictionary preparation shared mutable output")
	}
}

func TestValidID(t *testing.T) {
	for _, id := range []string{"", "aaa", "aaaaa", "AAAA\n", "abcd=", "ab/c", "éééé", "AA.A", "AA!A", "A[AA", "a`aa", "AA:A"} {
		if ValidID(id) {
			t.Errorf("accepted %q", id)
		}
	}
	for _, id := range []string{"abcd", "0dMf", "_-AZ", "0199", "azAZ"} {
		if !ValidID(id) {
			t.Errorf("rejected %q", id)
		}
	}
}

func TestPublishedCatalogAndImmutableLookup(t *testing.T) {
	loaded, err := Load(os.DirFS("../../data"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile("../../data/versions/v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Current) != string(seed) {
		t.Fatal("published catalog was changed while loading")
	}
	var catalog struct {
		Rules []struct{ Word, Category string }
	}
	if err := json.Unmarshal(loaded.Current, &catalog); err != nil {
		t.Fatal(err)
	}
	words := []string{}
	banwords := 0
	for _, rule := range catalog.Rules {
		words = append(words, rule.Word)
		if rule.Category == "banword" {
			banwords++
		}
	}
	if len(words) != 22 || banwords != 21 {
		t.Fatal("the complete 22-rule catalog must be retained")
	}
	dictionary := prepared(t, words...)
	if dictionary.ID != "0dMf" || !slices.Contains(dictionary.Words, "денчик") {
		t.Fatalf("historical catalog ID changed: %#v", dictionary)
	}
	matches := loaded.Lookup("0dMf")
	if !reflect.DeepEqual(matches, []Dictionary{dictionary}) {
		t.Fatalf("lookup differs: %#v", matches)
	}
	matches[0].ID, matches[0].Digest, matches[0].Words[0] = "bad", "bad", "bad"
	if !reflect.DeepEqual(loaded.Lookup("0dMf"), []Dictionary{dictionary}) {
		t.Fatal("a caller mutated the immutable index")
	}
	if got := loaded.Lookup("zzzz"); got == nil || len(got) != 0 {
		t.Fatalf("unknown lookup must produce an empty array: %#v", got)
	}
	loaded.Current[0] = '!'
	if loaded.Lookup("0dMf")[0].ID != "0dMf" {
		t.Fatal("public catalog bytes share mutable index state")
	}
}

func TestHistoricalVersionsAndRealCollisionLimit(t *testing.T) {
	loaded, err := Load(catalogFS(t, []string{"old", "new", "OLD"}, "v2"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(loaded.Current), `"new"`) {
		t.Fatal("current catalog does not follow manifest.current")
	}
	aliases := catalogFS(t, []string{"old", "new"}, "v1")
	aliases["manifest.json"].Data = []byte(`{"current":"v1","versions":["v1","v2"],"Current":"v2","Versions":["v3"]}`)
	withAliases, err := Load(aliases)
	if err != nil || !strings.Contains(string(withAliases.Current), `"old"`) {
		t.Fatalf("case aliases changed the exact manifest fields: %v", err)
	}
	for _, word := range []string{"old", "new"} {
		dictionary := prepared(t, word)
		if !reflect.DeepEqual(loaded.Lookup(dictionary.ID), []Dictionary{dictionary}) {
			t.Fatal("old versions were lost or canonical duplicates retained")
		}
	}
	raw, err := os.ReadFile("testdata/collision-nine.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ID    string
		Words []string
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Words) != 9 {
		t.Fatalf("invalid real SHA24 collision fixture: %v", err)
	}
	for _, word := range fixture.Words {
		if prepared(t, word).ID != fixture.ID {
			t.Fatal("fixture does not contain a real SHA24 collision")
		}
	}
	for _, count := range []int{2, 8} {
		loaded, err := Load(catalogFS(t, fixture.Words[:count], "v1"))
		if err != nil {
			t.Fatal(err)
		}
		matches := loaded.Lookup(fixture.ID)
		if len(matches) != count || matches[0].Digest == matches[1].Digest {
			t.Fatal("collision candidates were guessed or deduplicated by short ID")
		}
		for i, match := range matches {
			if !reflect.DeepEqual(match.Words, []string{fixture.Words[i]}) {
				t.Fatal("collision candidates did not retain every version")
			}
		}
	}
	if _, err := Load(catalogFS(t, fixture.Words, "v1")); err == nil || !strings.Contains(err.Error(), "too many dictionaries") {
		t.Fatalf("ninth distinct dictionary must prevent publication: %v", err)
	}
	withDuplicate := append(slices.Clone(fixture.Words[:8]), fixture.Words[0])
	if _, err := Load(catalogFS(t, withDuplicate, "v1")); err != nil {
		t.Fatalf("identical canonical data must not consume collision slots: %v", err)
	}
}

func TestInvalidManifestAndSeedFiles(t *testing.T) {
	for _, manifest := range []any{
		nil, false, 1, "x", []any{}, map[string]any{},
		map[string]any{"current": "v1", "versions": []any{}},
		map[string]any{"Current": "v1", "Versions": []string{"v1"}},
		map[string]any{"Current": "v1", "versions": []string{"v1"}},
		map[string]any{"current": "v1", "Versions": []string{"v1"}},
		map[string]any{"current": "v1", "versions": []any{nil}},
		map[string]any{"current": "v2", "versions": []string{"v1"}},
		map[string]any{"current": "v1", "versions": []string{"v1", "v1"}},
		map[string]any{"current": "v1", "versions": make([]string, 65)},
	} {
		files := fstest.MapFS{"manifest.json": &fstest.MapFile{Data: encoded(t, manifest)}}
		if _, err := Load(files); err == nil {
			t.Errorf("accepted invalid manifest %#v", manifest)
		}
	}
	for _, version := range []string{"../escape", "v0", "v01", "v1000000", "v1\n"} {
		files := fstest.MapFS{"manifest.json": &fstest.MapFile{Data: encoded(t, map[string]any{"current": version, "versions": []string{version}})}}
		if _, err := Load(files); err == nil {
			t.Errorf("accepted invalid version %q", version)
		}
	}
	if _, err := Load(fstest.MapFS{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing manifest error lost: %v", err)
	}
	missing := catalogFS(t, []string{"word"}, "v1")
	delete(missing, "versions/v1.json")
	if _, err := Load(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing version error lost: %v", err)
	}
	for _, raw := range [][]byte{[]byte("{"), {0xff}, []byte(strings.Repeat(" ", MaxFileBytes+1))} {
		for _, name := range []string{"manifest.json", "versions/v1.json"} {
			files := catalogFS(t, []string{"word"}, "v1")
			files[name] = &fstest.MapFile{Data: raw}
			if _, err := Load(files); err == nil {
				t.Errorf("accepted invalid seed %s", name)
			}
		}
	}
}

func TestCatalogValidation(t *testing.T) {
	variants := func(value any) map[string]any { c := ruleCatalog("word"); c["variants"] = value; return c }
	rules := func(value any) map[string]any { c := ruleCatalog("word"); c["rules"] = value; return c }
	for _, value := range []any{
		nil, false, 1, "x", []any{}, map[string]any{},
		variants(nil), variants([]any{}), variants([]any{nil}), variants([]any{1}),
		variants([]any{""}), variants([]any{" \ufeff\u2028"}), variants([]any{strings.Repeat("x", 101)}),
		variants(make([]any, 2501)), rules(nil), rules(1), rules([]any{}), rules(make([]any, 51)),
		rules([]any{nil}), rules([]any{1}), rules([]any{"word"}),
	} {
		if _, err := validateCatalog(encoded(t, value), true); err == nil {
			t.Errorf("accepted invalid catalog %#v", value)
		}
	}
	for key, value := range map[string]any{"format": "other", "version": 2} {
		c := ruleCatalog("word")
		c[key] = value
		if _, err := validateCatalog(encoded(t, c), true); err == nil {
			t.Errorf("accepted invalid %s", key)
		}
	}
	for _, override := range []map[string]any{
		{"word": nil}, {"word": ""}, {"word": "x x"}, {"word": strings.Repeat("x", 51)}, {"word": strings.Repeat("𐐀", 26)},
		{"category": nil}, {"category": "other"}, {"variantIds": nil}, {"variantIds": []any{}}, {"variantIds": make([]int, 51)},
		{"variantIds": []any{nil}}, {"variantIds": []any{"0"}}, {"variantIds": []any{-1}}, {"variantIds": []any{0.1}}, {"variantIds": []any{1}},
		{"matchMode": nil}, {"matchMode": "other"}, {"replaceMode": nil}, {"replaceMode": "other"}, {"encode": nil}, {"encode": "true"},
	} {
		catalog := ruleCatalog("word")
		rule := catalog["rules"].([]any)[0].(map[string]any)
		for key, value := range override {
			rule[key] = value
		}
		files := catalogFS(t, []string{"word"}, "v1")
		files["versions/v1.json"].Data = encoded(t, catalog)
		if _, err := Load(files); err == nil {
			t.Errorf("accepted invalid rule override %#v", override)
		}
	}
	valid := ruleCatalog(strings.Repeat("𐐀", 25))
	valid["variants"] = []any{"\u0085"} // JS trim does not remove NEL.
	rule := valid["rules"].([]any)[0].(map[string]any)
	rule["matchMode"], rule["replaceMode"] = "substring", "match"
	if _, err := validateCatalog(encoded(t, valid), true); err != nil {
		t.Fatalf("valid functional modes, NEL and UTF-16 length rejected: %v", err)
	}
	if _, err := validateCatalog([]byte("{"), true); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

type failingFS struct{ closed bool }
type failingFile struct{ owner *failingFS }

func (f *failingFS) Open(string) (fs.File, error) { return &failingFile{f}, nil }
func (f *failingFile) Read([]byte) (int, error)   { return 0, errors.New("injected read failure") }
func (f *failingFile) Close() error               { f.owner.closed = true; return nil }
func (f *failingFile) Stat() (fs.FileInfo, error) { return nil, errors.New("unused stat") }

func TestReadFailureClosesFile(t *testing.T) {
	fsys := &failingFS{}
	if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), "injected read failure") || !fsys.closed {
		t.Fatalf("read error did not close the file: %v, closed=%v", err, fsys.closed)
	}
}

func TestConcurrentCanonicalizationAndLookup(t *testing.T) {
	catalog, err := Load(os.DirFS("../../data"))
	if err != nil {
		t.Fatal(err)
	}
	want := prepared(t, "ΟΣ", "İ", "E\u0301")
	var workers sync.WaitGroup
	for range 24 {
		workers.Go(func() {
			for range 50 {
				got, err := PrepareDictionary([]string{"ΟΣ", "İ", "E\u0301"})
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("concurrent canonicalization differs: %v", err)
				}
				matches := catalog.Lookup("0dMf")
				matches[0].Words[0] = "caller-local mutation"
			}
		})
	}
	workers.Wait()
	if len(catalog.Lookup("0dMf")) != 1 {
		t.Fatal("concurrent callers corrupted the catalog")
	}
}
