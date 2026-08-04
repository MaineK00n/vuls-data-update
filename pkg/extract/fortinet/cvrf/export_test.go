package cvrf

// Exports for the cvrf_test package.

// ProductVersion aliases the unexported productVersion so external tests can
// build a product map for ToCriterion.
type ProductVersion = productVersion

// NewProductVersion constructs a ProductVersion from a product name and a
// version branch name.
func NewProductVersion(productName, version string) ProductVersion {
	return productVersion{productName: productName, version: version}
}

// KnownAffectedCriterions exposes knownAffectedCriterions for
// whitelist-enforcement tests.
var KnownAffectedCriterions = knownAffectedCriterions

// ExtractData exposes the per-advisory extract function for status-type
// validation tests.
var ExtractData = extract

// ExtractReferenceURLs exposes extractReferenceURLs for reference-parsing tests.
var ExtractReferenceURLs = extractReferenceURLs

// SupplementCriterions exposes supplementCriterions for whole-table
// validation tests.
var SupplementCriterions = supplementCriterions

// SupplementIDs returns every advisory ID in the supplement table, so tests
// can validate that each entry builds cleanly.
func SupplementIDs() []string {
	ids := make([]string, 0, len(supplementTable))
	for id := range supplementTable {
		ids = append(ids, id)
	}
	return ids
}

// SupplementTable exposes the table for the whole-product guard test, which
// injects (and removes) a synthetic unaudited row.
var SupplementTable = supplementTable

// SupplementProduct aliases the unexported supplementProduct for the guard
// test's synthetic row.
type SupplementProduct = supplementProduct
