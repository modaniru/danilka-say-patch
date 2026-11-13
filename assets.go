// Package banwords bundles the immutable published dictionaries and API contract.
package banwords

import (
	"embed"
	"io/fs"
)

//go:embed data/manifest.json data/versions/*.json
var data embed.FS

//go:embed openapi.json
var OpenAPI []byte

// BundledData is independent of the checkout directory and executable location.
func BundledData() fs.FS {
	// The literal is a valid fs path; fs.Sub cannot fail for this input.
	sub, _ := fs.Sub(data, "data")
	return sub
}
