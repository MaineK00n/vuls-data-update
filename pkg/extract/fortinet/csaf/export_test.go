package csaf

// Exports for the csaf_test package.

// ProductRef aliases the unexported productRef so external tests can build a
// refMap for ToCriterion.
type ProductRef = productRef

// NewProductRef constructs a ProductRef from a CPE and a version expression.
func NewProductRef(cpe, versionExp string) ProductRef {
	return productRef{cpe: cpe, versionExp: versionExp}
}

// ToCriterion exposes toCriterion for whitelist-enforcement tests.
var ToCriterion = toCriterion
