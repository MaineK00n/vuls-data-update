// Package category holds the body of a category, which is what CWE called a
// grouping before 5.0. Data extracted since then has a grouping.Grouping in
// its place; see CWE.Category.
package category

import (
	"cmp"
	"slices"

	mappingnotesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes"
	memberTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/member"
	noteTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/note"
	taxonomymappingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/taxonomymapping"
)

// Category is the body of an entry of Kind "category", in data extracted
// before CWE 5.0.
type Category struct {
	Members          []memberTypes.Member                   `json:"members,omitempty"`
	TaxonomyMappings []taxonomymappingTypes.TaxonomyMapping `json:"taxonomy_mappings,omitempty"`
	Notes            []noteTypes.Note                       `json:"notes,omitempty"`
	MappingNotes     mappingnotesTypes.MappingNotes         `json:"mapping_notes,omitzero"`
}

func (c *Category) Sort() {
	for i := range c.Members {
		(&c.Members[i]).Sort()
	}
	slices.SortFunc(c.Members, memberTypes.Compare)
	slices.SortFunc(c.TaxonomyMappings, taxonomymappingTypes.Compare)
	slices.SortFunc(c.Notes, noteTypes.Compare)
	c.MappingNotes.Sort()
}

func Compare(x, y Category) int {
	return cmp.Or(
		slices.CompareFunc(x.Members, y.Members, memberTypes.Compare),
		slices.CompareFunc(x.TaxonomyMappings, y.TaxonomyMappings, taxonomymappingTypes.Compare),
		slices.CompareFunc(x.Notes, y.Notes, noteTypes.Compare),
		mappingnotesTypes.Compare(x.MappingNotes, y.MappingNotes),
	)
}
