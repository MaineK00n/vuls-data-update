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
// validation tests; guard tests pass synthetic tables instead of mutating
// the production one.
var SupplementCriterions = supplementCriterions

// SupplementTable exposes the production table as a read-only view for the
// whole-table validation tests.
var SupplementTable = supplementTable

// SupplementProduct / SupplementRange alias the unexported row types so
// tests can read production rows and build synthetic ones.
type (
	SupplementProduct = supplementProduct
	SupplementRange   = supplementRange
)

// AdvisoryProduct aliases the unexported advisoryProduct so tests can read
// the whole-product allowlist keys.
type AdvisoryProduct = advisoryProduct

// WholeProductAudited exposes the whole-product allowlist as a read-only
// view, so tests can check every entry still backs a live constraint-less
// row (a stale entry would silently pre-authorize a future whole-product
// widening).
var WholeProductAudited = wholeProductAudited
