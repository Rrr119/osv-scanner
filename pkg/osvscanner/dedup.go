package osvscanner

import (
	"cmp"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scanner/v2/internal/imodels"
)

type packageIdentity struct {
	ecosystem string
	purl      string
	purlType  string
	name      string
	version   string
	repo      string
	commit    string
	layer     int
}

func identityOf(pkg *extractor.Package) packageIdentity {
	parsed := imodels.ParsePackage(pkg)
	identity := packageIdentity{
		ecosystem: parsed.Ecosystem.String(),
		purlType:  pkg.PURLType,
		name:      parsed.Name,
		version:   parsed.Version,
		commit:    parsed.Commit,
		layer:     -1,
	}

	if purl := pkg.PURL(); purl != nil {
		identity.purl = purl.String()
	}

	if pkg.SourceCode != nil {
		identity.repo = pkg.SourceCode.Repo
		if pkg.SourceCode.Commit != "" {
			identity.commit = pkg.SourceCode.Commit
		}
	}

	if pkg.LayerMetadata != nil {
		identity.layer = pkg.LayerMetadata.Index
	}

	return identity
}

// dedupInventory collapses packages that identify the same dependency. This is
// required for monorepos where the same package can be discovered through
// multiple lockfiles. The first package wins, while metadata from duplicates is
// merged into it and vulnerability package references are remapped.
func dedupInventory(inv *inventory.Inventory) {
	remappedPackages := make(map[*extractor.Package]*extractor.Package, len(inv.Packages))

	if len(inv.Packages) > 0 {
		slices.SortFunc(inv.Packages, inventorySort)

		uniquePackages := make(map[packageIdentity]*extractor.Package, len(inv.Packages))

		for _, pkg := range inv.Packages {
			identity := identityOf(pkg)
			if kept, ok := uniquePackages[identity]; ok {
				mergePackage(kept, pkg)
				remappedPackages[pkg] = kept

				continue
			}

			uniquePackages[identity] = pkg
		}

		inv.Packages = slices.Collect(maps.Values(uniquePackages))
		slices.SortFunc(inv.Packages, inventorySort)

		for _, vuln := range inv.PackageVulns {
			if kept, ok := remappedPackages[vuln.Package]; ok {
				vuln.Package = kept
			}
		}
	}

	inv.PackageVulns = dedupPackageVulns(inv.PackageVulns)
}

func mergePackage(kept, duplicate *extractor.Package) {
	if kept == duplicate {
		return
	}

	kept.Plugins = mergeUnique(kept.Plugins, duplicate.Plugins)
	kept.Licenses = mergeUnique(kept.Licenses, duplicate.Licenses)
	kept.Deprecated = kept.Deprecated || duplicate.Deprecated

	if kept.SourceCode == nil {
		kept.SourceCode = duplicate.SourceCode
	}
	if kept.Metadata == nil {
		kept.Metadata = duplicate.Metadata
	}
	if kept.LayerMetadata == nil {
		kept.LayerMetadata = duplicate.LayerMetadata
	}

	if duplicate.Location.Descriptor != nil {
		mergeRelatedLocation(kept, *duplicate.Location.Descriptor)
	}
	for _, related := range duplicate.Location.Related {
		mergeRelatedLocation(kept, related)
	}

	if len(duplicate.ParentIDs) > 0 {
		if kept.ParentIDs == nil {
			kept.ParentIDs = make(map[string]bool, len(duplicate.ParentIDs))
		}
		for id := range duplicate.ParentIDs {
			kept.ParentIDs[id] = true
		}
	}

	for _, signal := range duplicate.ExploitabilitySignals {
		if !slices.ContainsFunc(kept.ExploitabilitySignals, func(existing *vex.PackageExploitabilitySignal) bool {
			return existing.Plugin == signal.Plugin &&
				existing.Justification == signal.Justification &&
				existing.MatchesAllVulns == signal.MatchesAllVulns &&
				slices.Equal(existing.VulnIdentifiers, signal.VulnIdentifiers)
		}) {
			kept.ExploitabilitySignals = append(kept.ExploitabilitySignals, signal)
		}
	}
}

func mergeRelatedLocation(pkg *extractor.Package, candidate location.Location) {
	if candidate.File == nil {
		return
	}
	if pkg.Location.Descriptor != nil && sameLocation(*pkg.Location.Descriptor, candidate) {
		return
	}
	if slices.ContainsFunc(pkg.Location.Related, func(existing location.Location) bool {
		return sameLocation(existing, candidate)
	}) {
		return
	}

	pkg.Location.Related = append(pkg.Location.Related, candidate)
}

func sameLocation(a, b location.Location) bool {
	if a.File == nil || b.File == nil {
		return a.File == nil && b.File == nil
	}

	return a.File.Path == b.File.Path && a.File.LineNumber == b.File.LineNumber
}

func mergeUnique(a, b []string) []string {
	result := slices.Clone(a)
	for _, value := range b {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}

	return result
}

func dedupPackageVulns(vulns []*inventory.PackageVuln) []*inventory.PackageVuln {
	if len(vulns) == 0 {
		return vulns
	}

	type vulnIdentity struct {
		pkg    packageIdentity
		vulnID string
	}

	uniqueVulns := make(map[vulnIdentity]*inventory.PackageVuln, len(vulns))
	for _, vuln := range vulns {
		identity := vulnIdentity{
			pkg:    identityOf(vuln.Package),
			vulnID: vuln.Vulnerability.GetId(),
		}

		kept, ok := uniqueVulns[identity]
		if !ok {
			uniqueVulns[identity] = vuln
			continue
		}

		kept.Plugins = mergeUnique(kept.Plugins, vuln.Plugins)
		for _, signal := range vuln.ExploitabilitySignals {
			if !slices.ContainsFunc(kept.ExploitabilitySignals, func(existing *vex.FindingExploitabilitySignal) bool {
				return existing.Plugin == signal.Plugin && existing.Justification == signal.Justification
			}) {
				kept.ExploitabilitySignals = append(kept.ExploitabilitySignals, signal)
			}
		}
	}

	result := slices.Collect(maps.Values(uniqueVulns))
	slices.SortFunc(result, func(a, b *inventory.PackageVuln) int {
		return cmp.Or(
			inventorySort(a.Package, b.Package),
			cmp.Compare(a.Vulnerability.GetId(), b.Vulnerability.GetId()),
		)
	})

	return result
}
