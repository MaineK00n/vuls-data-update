package grouping

import (
	"cmp"
	"slices"

	mappingnotesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes"
	memberTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/member"
	noteTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/note"
	taxonomymappingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/taxonomymapping"
)

// Grouping is a collection of CWE entries sharing a characteristic. CWE 5.0
// renamed what earlier versions call a category to a grouping.
type Grouping struct {
	Members          []memberTypes.Member                   `json:"members,omitempty"`
	TaxonomyMappings []taxonomymappingTypes.TaxonomyMapping `json:"taxonomy_mappings,omitempty"`
	Notes            []noteTypes.Note                       `json:"notes,omitempty"`
	MappingNotes     mappingnotesTypes.MappingNotes         `json:"mapping_notes,omitzero"`
}

func (g *Grouping) Sort() {
	for i := range g.Members {
		(&g.Members[i]).Sort()
	}
	slices.SortFunc(g.Members, memberTypes.Compare)
	slices.SortFunc(g.TaxonomyMappings, taxonomymappingTypes.Compare)
	slices.SortFunc(g.Notes, noteTypes.Compare)
	g.MappingNotes.Sort()
}

func Compare(x, y Grouping) int {
	return cmp.Or(
		slices.CompareFunc(x.Members, y.Members, memberTypes.Compare),
		slices.CompareFunc(x.TaxonomyMappings, y.TaxonomyMappings, taxonomymappingTypes.Compare),
		slices.CompareFunc(x.Notes, y.Notes, noteTypes.Compare),
		mappingnotesTypes.Compare(x.MappingNotes, y.MappingNotes),
	)
}
