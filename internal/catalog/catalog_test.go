package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

func encoded(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func ruleCatalog() map[string]any {
	return map[string]any{
		"format": "saypatch-rules", "version": 1, "variants": []any{"first", "second"},
		"rules": []any{
			map[string]any{"word": "Part", "category": "safe", "variantIds": []any{0}, "matchMode": "word", "replaceMode": "word"},
			map[string]any{"word": "Other", "category": "banword", "variantIds": []any{1}, "matchMode": "substring", "replaceMode": "match"},
		},
	}
}
func loadBytes(raw []byte) (*Catalog, error) { return Load(fstest.MapFS{"catalog.json": {Data: raw}}) }
func loaded(t *testing.T, value any) *Catalog {
	t.Helper()
	c, err := loadBytes(encoded(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func clone(t *testing.T, value any) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(encoded(t, value), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSinglePublishedCatalog(t *testing.T) {
	c, err := Load(os.DirFS("../../data"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir("../../data")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "catalog.json" {
		t.Fatal("data must contain only one Git-managed catalog")
	}
	raw, err := os.ReadFile("../../data/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected, got map[string]any
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(c.Body(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatal("functional fields were lost")
	}
	rules := got["rules"].([]any)
	if len(rules) != 22 || len(got["variants"].([]any)) != 22 {
		t.Fatal("complete source catalog not retained")
	}
	banwords := 0
	for _, entry := range rules {
		rule := entry.(map[string]any)
		if len(rule) != 5 || rule["replaceMode"] != "word" {
			t.Fatal("functional rule modes missing")
		}
		if rule["category"] == "banword" {
			banwords++
		}
		want := "substring"
		if rule["word"] == "Денчик" || rule["word"] == "жид" {
			want = "word"
		}
		if rule["matchMode"] != want {
			t.Fatal("published matching policy changed")
		}
	}
	if banwords != 21 {
		t.Fatal("original categories changed")
	}
	sum := sha256.Sum256(c.Body())
	if c.Hash() != hex.EncodeToString(sum[:]) || len(c.Hash()) != 64 {
		t.Fatal("hash does not cover exact body bytes")
	}
}

func TestStableWireHashAndImmutableSnapshot(t *testing.T) {
	one := loaded(t, ruleCatalog())
	pretty, err := json.MarshalIndent(ruleCatalog(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	two, err := loadBytes(append([]byte(" \n"), pretty...))
	if err != nil {
		t.Fatal(err)
	}
	// Equivalent property order and numeric notation have the same JSON meaning.
	reordered := []byte(`{"rules":[{"replaceMode":"word","matchMode":"word","variantIds":[0.0],"category":"safe","word":"Part"},{"category":"banword","word":"Other","variantIds":[1],"replaceMode":"match","matchMode":"substring"}],"version":1.0,"format":"saypatch-rules","variants":["first","second"]}`)
	three, err := loadBytes(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if one.Hash() != two.Hash() || one.Hash() != three.Hash() || string(one.Body()) != string(three.Body()) {
		t.Fatal("formatting or key order changed freshness")
	}
	body := one.Body()
	body[0] = '!'
	if one.Body()[0] != '{' || one.Hash() != two.Hash() {
		t.Fatal("caller mutated the snapshot")
	}
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			for range 30 {
				b := one.Body()
				b[0] = '!'
				if one.Hash() != two.Hash() {
					t.Error("concurrent snapshot changed")
				}
			}
		})
	}
	workers.Wait()
}

func TestHashIncludesEveryFunctionalValueAndArrayOrder(t *testing.T) {
	base := ruleCatalog()
	before := loaded(t, base).Hash()
	changes := []func(map[string]any){
		func(v map[string]any) { v["variants"].([]any)[0] = "changed" },
		func(v map[string]any) { a := v["variants"].([]any); a[0], a[1] = a[1], a[0] },
		func(v map[string]any) { a := v["rules"].([]any); a[0], a[1] = a[1], a[0] },
	}
	for key, value := range map[string]any{"word": "changed", "category": "banword", "variantIds": []any{1}, "matchMode": "substring", "replaceMode": "match"} {
		changes = append(changes, func(v map[string]any) { v["rules"].([]any)[0].(map[string]any)[key] = value })
	}
	for i, change := range changes {
		v := clone(t, base)
		change(v)
		if loaded(t, v).Hash() == before {
			t.Fatalf("functional change %d did not affect hash", i)
		}
	}
	v := ruleCatalog()
	v["rules"].([]any)[0].(map[string]any)["word"] = "E\u0301"
	c := loaded(t, v)
	var got map[string]any
	json.Unmarshal(c.Body(), &got)
	if got["rules"].([]any)[0].(map[string]any)["word"] != "E\u0301" {
		t.Fatal("server must preserve source strings without normalization")
	}
	v["rules"].([]any)[0].(map[string]any)["word"] = "É"
	if loaded(t, v).Hash() == c.Hash() {
		t.Fatal("hash must follow exact functional source content")
	}
}

func TestInvalidCatalogAndUnknownFields(t *testing.T) {
	for _, value := range []any{nil, false, 1, "x", []any{}, map[string]any{}} {
		if _, err := loadBytes(encoded(t, value)); err == nil {
			t.Errorf("accepted invalid root %#v", value)
		}
	}
	for _, override := range []map[string]any{
		{"format": "other"}, {"version": 2}, {"variants": nil}, {"variants": []any{}}, {"variants": []any{nil}},
		{"variants": []any{1}}, {"variants": []any{""}}, {"variants": []any{" \ufeff\u2028"}}, {"variants": []any{strings.Repeat("x", 101)}},
		{"variants": make([]any, 2501)}, {"rules": nil}, {"rules": 1}, {"rules": []any{}}, {"rules": make([]any, 51)},
		{"rules": []any{nil}}, {"rules": []any{1}}, {"rules": []any{"x"}}, {"unexpected": true}, {"encodingEnabled": false},
	} {
		v := ruleCatalog()
		for k, val := range override {
			v[k] = val
		}
		if _, err := loadBytes(encoded(t, v)); err == nil {
			t.Errorf("accepted invalid catalog %#v", override)
		}
	}
	for _, override := range []map[string]any{
		{"word": nil}, {"word": ""}, {"word": "a b"}, {"word": "<script>"}, {"word": "a\n"}, {"word": strings.Repeat("a", 51)},
		{"word": strings.Repeat("𐐀", 26)}, {"category": nil}, {"category": "other"}, {"variantIds": nil}, {"variantIds": []any{}},
		{"variantIds": make([]any, 51)}, {"variantIds": []any{nil}}, {"variantIds": []any{"0"}}, {"variantIds": []any{-1}},
		{"variantIds": []any{0.1}}, {"variantIds": []any{2}}, {"matchMode": nil}, {"matchMode": "other"}, {"replaceMode": nil},
		{"replaceMode": "other"}, {"unexpected": true}, {"encode": false}, {"encodingEnabled": false},
	} {
		v := ruleCatalog()
		r := v["rules"].([]any)[0].(map[string]any)
		for k, val := range override {
			r[k] = val
		}
		if _, err := loadBytes(encoded(t, v)); err == nil {
			t.Errorf("accepted invalid rule %#v", override)
		}
	}
	for _, name := range []string{"matchMode", "replaceMode"} {
		v := ruleCatalog()
		delete(v["rules"].([]any)[0].(map[string]any), name)
		if _, err := loadBytes(encoded(t, v)); err == nil {
			t.Fatalf("accepted missing mode %s", name)
		}
	}
	valid := ruleCatalog()
	valid["variants"] = []any{"\u0085", "second"}
	valid["rules"].([]any)[0].(map[string]any)["word"] = strings.Repeat("𐐀", 25)
	loaded(t, valid)
}

func TestFileAndCanonicalResponseBounds(t *testing.T) {
	if _, err := Load(fstest.MapFS{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing catalog: %v", err)
	}
	for _, raw := range [][]byte{[]byte("{"), {0xff}, []byte(strings.Repeat(" ", MaxFileBytes+1)), []byte(`{"version":1e400}`)} {
		if _, err := loadBytes(raw); err == nil {
			t.Fatal("accepted malformed or oversized file")
		}
	}
	// A small source with HTML characters can grow during deterministic JSON
	// encoding; bound the actual wire bytes as well as the source file.
	v := ruleCatalog()
	variants := make([]any, 220)
	for i := range variants {
		variants[i] = strings.Repeat("<", 50)
	}
	v["variants"] = variants
	body := string(encoded(t, v))
	body = strings.ReplaceAll(body, `\u003c`, "<")
	if len(body) >= MaxFileBytes {
		t.Fatal("fixture must be below source limit")
	}
	if _, err := loadBytes([]byte(body)); err == nil || !strings.Contains(err.Error(), "response too large") {
		t.Fatalf("wire response limit not enforced: %v", err)
	}
}

type failingFS struct{ closed bool }
type failingFile struct{ owner *failingFS }

func (f *failingFS) Open(string) (fs.File, error) { return &failingFile{f}, nil }
func (f *failingFile) Read([]byte) (int, error)   { return 0, errors.New("injected read failure") }
func (f *failingFile) Close() error               { f.owner.closed = true; return nil }
func (f *failingFile) Stat() (fs.FileInfo, error) { return nil, errors.New("unused stat") }
func TestReadFailureClosesFile(t *testing.T) {
	f := &failingFS{}
	if _, err := Load(f); err == nil || !f.closed {
		t.Fatalf("read failure must close file: %v", err)
	}
}
