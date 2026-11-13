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
	for _, version := range []string{"v1", "v2"} {
		seed, err := fs.ReadFile(BundledData(), "versions/"+version+".json")
		if err != nil || !json.Valid(seed) {
			t.Fatalf("bundled seed %s: %v", version, err)
		}
	}
	if !json.Valid(OpenAPI) {
		t.Fatal("OpenAPI is not valid JSON")
	}
}
