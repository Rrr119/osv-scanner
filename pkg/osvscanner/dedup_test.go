package osvscanner

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestDedupInventoryMergesMonorepoPackages(t *testing.T) {
	t.Parallel()

	first := &extractor.Package{
		Name:     "ansi-html",
		Version:  "0.0.1",
		PURLType: purl.TypeNPM,
		Plugins:  []string{"npm/package-lock"},
		Licenses: []string{"Apache-2.0"},
		Location: extractor.LocationFromPath("services/admin/package-lock.json"),
	}
	second := &extractor.Package{
		Name:     "ansi-html",
		Version:  "0.0.1",
		PURLType: purl.TypeNPM,
		Plugins:  []string{"npm/yarn"},
		Licenses: []string{"MIT"},
		Location: extractor.LocationFromPath("services/web/yarn.lock"),
	}
	otherEcosystem := &extractor.Package{
		Name:     "ansi-html",
		Version:  "0.0.1",
		PURLType: purl.TypePyPi,
		Plugins:  []string{"python/requirements"},
		Location: extractor.LocationFromPath("services/api/requirements.txt"),
	}
	differentVersion := &extractor.Package{
		Name:     "ansi-html",
		Version:  "0.0.8",
		PURLType: purl.TypeNPM,
		Plugins:  []string{"npm/package-lock"},
		Location: extractor.LocationFromPath("services/docs/package-lock.json"),
	}

	vulnID := "GHSA-test-0000-0000"
	inv := inventory.Inventory{
		Packages: []*extractor.Package{first, second, otherEcosystem, differentVersion},
		PackageVulns: []*inventory.PackageVuln{
			{Package: first, Vulnerability: &osvschema.Vulnerability{Id: vulnID}, Plugins: []string{"vulnmatch/osvlocal"}},
			{Package: second, Vulnerability: &osvschema.Vulnerability{Id: vulnID}, Plugins: []string{"vulnmatch/osvdev"}},
		},
	}

	dedupInventory(&inv)

	if len(inv.Packages) != 3 {
		t.Fatalf("dedupInventory() kept %d packages, want 3", len(inv.Packages))
	}

	kept := inv.Packages[0]
	if kept.Name != "ansi-html" || kept.Version != "0.0.1" || kept.PURLType != purl.TypeNPM {
		t.Fatalf("expected the npm ansi-html 0.0.1 package to be kept, got %#v", kept)
	}
	if !slices.Equal(kept.Plugins, []string{"npm/package-lock", "npm/yarn"}) {
		t.Errorf("kept plugins = %v, want merged plugins", kept.Plugins)
	}
	if !slices.Equal(kept.Licenses, []string{"Apache-2.0", "MIT"}) {
		t.Errorf("kept licenses = %v, want merged licenses", kept.Licenses)
	}
	if len(kept.Location.Related) != 1 || kept.Location.Related[0].PathOrEmpty() != "services/web/yarn.lock" {
		t.Errorf("related locations = %#v, want the duplicate lockfile location", kept.Location.Related)
	}

	if len(inv.PackageVulns) != 1 {
		t.Fatalf("dedupInventory() kept %d vulnerabilities, want 1", len(inv.PackageVulns))
	}
	if inv.PackageVulns[0].Package != kept {
		t.Errorf("vulnerability package was not remapped to the kept package")
	}
	if !slices.Equal(inv.PackageVulns[0].Plugins, []string{"vulnmatch/osvlocal", "vulnmatch/osvdev"}) {
		t.Errorf("vulnerability plugins = %v, want merged plugins", inv.PackageVulns[0].Plugins)
	}
}

func TestDedupInventoryKeepsDistinctSourceCodePackages(t *testing.T) {
	t.Parallel()

	first := &extractor.Package{
		Name:     "example",
		Version:  "1.0.0",
		PURLType: purl.TypeGolang,
		SourceCode: &extractor.SourceCodeIdentifier{
			Repo:   "https://example.com/first",
			Commit: "1111111",
		},
		Location: extractor.LocationFromPath("first/go.mod"),
	}
	second := &extractor.Package{
		Name:     "example",
		Version:  "1.0.0",
		PURLType: purl.TypeGolang,
		SourceCode: &extractor.SourceCodeIdentifier{
			Repo:   "https://example.com/second",
			Commit: "2222222",
		},
		Location: extractor.LocationFromPath("second/go.mod"),
	}

	inv := inventory.Inventory{Packages: []*extractor.Package{first, second}}
	dedupInventory(&inv)

	if len(inv.Packages) != 2 {
		t.Fatalf("dedupInventory() kept %d packages, want 2 distinct source-code packages", len(inv.Packages))
	}
}
