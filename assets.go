// Package banwords bundles the Git-managed catalog and API contract.
package banwords

import (
	"embed"
	"io/fs"
)

//go:embed data/catalog.json
var data embed.FS

//go:embed openapi.json
var OpenAPI []byte

// BundledData is independent of the checkout directory and executable location.
func BundledData() fs.FS {
	// The literal is a valid fs path; fs.Sub cannot fail for this input.
	sub, _ := fs.Sub(data, "data")
	return sub
}
