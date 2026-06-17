// Package linkguardfw is the root package for LinkGuard FW.
// It embeds the compiled frontend web assets so that the binary
// is fully self-contained.
package linkguardfw

import "embed"

// WebFS contains the compiled frontend files from web/dist/.
// Run `make build-frontend` to populate this directory before building.
//
//go:embed web/dist
var WebFS embed.FS
