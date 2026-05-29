package taxonomymapping

import "cmp"

// TaxonomyMapping represents a mapping from this CWE entry to an external
// taxonomy entry (OWASP / PCI-DSS / SEI CERT / WASC / etc.).
type TaxonomyMapping struct {
	TaxonomyName string `json:"taxonomy_name,omitempty"`
	EntryID      string `json:"entry_id,omitempty"`
	EntryName    string `json:"entry_name,omitempty"`
	MappingFit   string `json:"mapping_fit,omitempty"`
}

func Compare(x, y TaxonomyMapping) int {
	return cmp.Or(
		cmp.Compare(x.TaxonomyName, y.TaxonomyName),
		cmp.Compare(x.EntryID, y.EntryID),
		cmp.Compare(x.EntryName, y.EntryName),
		cmp.Compare(x.MappingFit, y.MappingFit),
	)
}
