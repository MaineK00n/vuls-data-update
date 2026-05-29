package mappingnotes

import (
	"cmp"
	"slices"

	reasonTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes/reason"
	suggestionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes/suggestion"
)

// MappingNotes captures the upstream Mapping_Notes element, which guides
// whether and how a CWE entry should be used to classify a CVE.
// Usage values include "Allowed", "Allowed-with-Review", "Discouraged"
// and "Prohibited".
type MappingNotes struct {
	Usage       string                       `json:"usage,omitempty"`
	Rationale   string                       `json:"rationale,omitempty"`
	Comments    string                       `json:"comments,omitempty"`
	Reasons     []reasonTypes.Reason         `json:"reasons,omitempty"`
	Suggestions []suggestionTypes.Suggestion `json:"suggestions,omitempty"`
}

func (m *MappingNotes) Sort() {
	slices.SortFunc(m.Reasons, reasonTypes.Compare)
	slices.SortFunc(m.Suggestions, suggestionTypes.Compare)
}

func Compare(x, y MappingNotes) int {
	return cmp.Or(
		cmp.Compare(x.Usage, y.Usage),
		cmp.Compare(x.Rationale, y.Rationale),
		cmp.Compare(x.Comments, y.Comments),
		slices.CompareFunc(x.Reasons, y.Reasons, reasonTypes.Compare),
		slices.CompareFunc(x.Suggestions, y.Suggestions, suggestionTypes.Compare),
	)
}
