package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func decodeObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPublishedFullCatalogPreservesImmutableV1(t *testing.T) {
	legacy, err := os.ReadFile("../../data/versions/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(legacy)
	if hex.EncodeToString(sum[:]) != "0f0905257ee84a3182efc0ea83a03339653accbcac6c0738cdaefffb8455b375" {
		t.Fatal("published v1 must remain byte-for-byte unchanged")
	}
	loaded, err := Load(os.DirFS("../../data"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("../../data/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeObject(t, manifest), map[string]any{"current": "v2", "versions": []any{"v1", "v2"}}) {
		t.Fatal("manifest must publish v2 and retain v1")
	}
	old := decodeObject(t, legacy)
	current := decodeObject(t, loaded.Current)
	want := decodeObject(t, legacy)
	for _, entry := range want["rules"].([]any) {
		rule := entry.(map[string]any)
		if _, exists := rule["matchMode"]; !exists {
			rule["matchMode"] = "word"
			if rule["category"] == "banword" {
				rule["matchMode"] = "substring"
			}
		}
		rule["replaceMode"] = "word"
	}
	if !reflect.DeepEqual(current, want) {
		t.Fatal("v2 must preserve every word, replacement, category and existing match exception")
	}
	if !reflect.DeepEqual(current["variants"], old["variants"]) || len(current["rules"].([]any)) != 22 {
		t.Fatal("full source catalog or replacement order was changed")
	}
	for _, entry := range current["rules"].([]any) {
		rule := entry.(map[string]any)
		if len(rule) != 5 || rule["replaceMode"] != "word" {
			t.Fatalf("functional rule fields missing or client-only flags present: %#v", rule)
		}
		if rule["word"] == "Денчик" || rule["word"] == "жид" {
			if rule["matchMode"] != "word" {
				t.Fatal("safe rule or whole-word exception changed")
			}
		} else if rule["matchMode"] != "substring" {
			t.Fatal("banword substring policy changed")
		}
	}
	matches := loaded.Lookup("0dMf")
	if len(matches) != 1 || len(matches[0].Words) != 22 {
		t.Fatal("adding functional fields must not change hash1 or create duplicate candidates")
	}
}

func TestOnlyCurrentCatalogRequiresExplicitFunctionalModes(t *testing.T) {
	for _, omitted := range [][]string{{"matchMode"}, {"replaceMode"}, {"matchMode", "replaceMode"}} {
		files := catalogFS(t, []string{"word", "word"}, "v2")
		legacy := ruleCatalog("word")
		rule := legacy["rules"].([]any)[0].(map[string]any)
		for _, field := range omitted {
			delete(rule, field)
		}
		files["versions/v1.json"].Data = encoded(t, legacy)
		loaded, err := Load(files)
		if err != nil || len(loaded.Lookup(prepared(t, "word").ID)) != 1 {
			t.Fatalf("legacy optional modes must remain readable for lookup: %v", err)
		}
		files["manifest.json"].Data = []byte(`{"current":"v1","versions":["v1","v2"]}`)
		if _, err := Load(files); err == nil {
			t.Fatalf("current catalog accepted missing modes %v", omitted)
		}
	}
}

func TestFunctionalModesRemainExplicitAndDoNotAffectDictionaryIdentity(t *testing.T) {
	files := catalogFS(t, []string{"source", "source"}, "v2")
	functional := ruleCatalog("source")
	rule := functional["rules"].([]any)[0].(map[string]any)
	rule["matchMode"], rule["replaceMode"] = "substring", "match"
	files["versions/v2.json"].Data = encoded(t, functional)
	loaded, err := Load(files)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeObject(t, loaded.Current), decodeObject(t, encoded(t, functional))) {
		t.Fatal("substring matching and matched-fragment replacement flags were not preserved")
	}
	if len(loaded.Lookup(prepared(t, "source").ID)) != 1 {
		t.Fatal("functional modes must not participate in the sp/1 dictionary hash")
	}
}

func TestUnknownCatalogAndRuleFieldsAreRejectedGenerically(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, name := range []string{"unexpected", "encodingEnabled", "Encode", "rulesMetadata"} {
			value := ruleCatalog("word")
			value[name] = false
			if _, err := validateCatalog(encoded(t, value), complete); err == nil {
				t.Errorf("unknown catalog field %q accepted", name)
			}
		}
		for _, name := range []string{"unexpected", "encode", "encodingEnabled", "MatchMode"} {
			value := ruleCatalog("word")
			value["rules"].([]any)[0].(map[string]any)[name] = false
			if _, err := validateCatalog(encoded(t, value), complete); err == nil {
				t.Errorf("unknown rule field %q accepted", name)
			}
		}
	}
}
