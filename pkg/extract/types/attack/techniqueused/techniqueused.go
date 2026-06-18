package techniqueused

import (
	"cmp"
	"slices"

	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

type TechniqueUsed struct {
	ID          string                     `json:"id"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"` // per-edge citations from STIX relationship.external_references
}

func (t *TechniqueUsed) Sort() {
	slices.SortFunc(t.References, referenceTypes.Compare)
}

func Compare(x, y TechniqueUsed) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Description, y.Description),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
	)
}
