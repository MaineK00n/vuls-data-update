package csaf

// Exports for the csaf_test package.

// ProductRef aliases the unexported productRef so external tests can build a
// refMap for ToCriterions.
type ProductRef = productRef

// NewProductRef constructs a ProductRef from a product name and a version
// expression. The name is resolved to a CPE (and whitelist-checked) in
// ToCriterions.
func NewProductRef(productName, versionExp string) ProductRef {
	return productRef{productName: productName, versionExp: versionExp}
}

// ToCriterions exposes toCriterions for whitelist-enforcement tests.
var ToCriterions = toCriterions
