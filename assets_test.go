package banwords

import (
	"encoding/json"
	"io/fs"
	"testing"
)

func TestEmbeddedAssets(t *testing.T) {
	data, err := fs.ReadFile(BundledData(), "manifest.json")
	if err != nil || !json.Valid(data) {
		t.Fatalf("bundled manifest: %s %v", data, err)
	}
	seed, err := fs.ReadFile(BundledData(), "versions/v1.json")
	if err != nil || !json.Valid(seed) {
		t.Fatalf("bundled seed: %v", err)
	}
	if !json.Valid(OpenAPI) {
		t.Fatal("OpenAPI is not valid JSON")
	}
}
