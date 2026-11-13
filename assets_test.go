package banwords

import (
	"encoding/json"
	"io/fs"
	"testing"
)

func TestEmbeddedAssets(t *testing.T) {
	catalog, err := fs.ReadFile(BundledData(), "catalog.json")
	if err != nil || !json.Valid(catalog) {
		t.Fatalf("bundled catalog: %v", err)
	}
	files, err := fs.ReadDir(BundledData(), ".")
	if err != nil || len(files) != 1 || files[0].Name() != "catalog.json" {
		t.Fatal("only one active catalog must be embedded")
	}
	if !json.Valid(OpenAPI) {
		t.Fatal("OpenAPI is not valid JSON")
	}
}
