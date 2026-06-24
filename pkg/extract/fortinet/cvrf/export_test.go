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

// IsExactVersion exposes isExactVersion for version-classification tests.
var IsExactVersion = isExactVersion

// ExtractData exposes the per-advisory extract function for status-type
// validation tests.
var ExtractData = extract
