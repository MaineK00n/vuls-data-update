package csaf

// Exports for the csaf_test package.

// ProductRef aliases the unexported productRef so external tests can build a
// refMap for ToCriterion.
type ProductRef = productRef

// NewProductRef constructs a ProductRef from a product name and a version
// expression. The name is resolved to a CPE (and whitelist-checked) in
// ToCriterion.
func NewProductRef(productName, versionExp string) ProductRef {
	return productRef{productName: productName, versionExp: versionExp}
}

// ToCriterion exposes toCriterion for whitelist-enforcement tests.
var ToCriterion = toCriterion
