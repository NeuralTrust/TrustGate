// Command plugincatalog writes the plugin catalog as JSON.
//
// The app repo's console (brand map, config forms, translated strings) is
// maintained by hand, and this is what its CI check diffs against so a
// guardrail plugin cannot ship here without a brand entry and strings, or be
// removed here while the console still carries bespoke handling for it. See
// RUN-1643.
//
//	go run ./scripts/plugincatalog > plugin-catalog.json
package main

import (
	"fmt"
	"os"

	"github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

func main() {
	data, err := plugins.CatalogManifestJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugincatalog: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "plugincatalog: %v\n", err)
		os.Exit(1)
	}
}
