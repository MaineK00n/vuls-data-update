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

// ToCriterion exposes toCriterion for whitelist-enforcement tests.
var ToCriterion = toCriterion
