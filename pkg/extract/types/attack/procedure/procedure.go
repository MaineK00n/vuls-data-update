package procedure

import (
	"cmp"
	"slices"

	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

type Procedure struct {
	AttackerID  string                     `json:"attacker_id"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"` // per-edge citations from STIX relationship.external_references
}

func (p *Procedure) Sort() {
	slices.SortFunc(p.References, referenceTypes.Compare)
}

func Compare(x, y Procedure) int {
	return cmp.Or(
		cmp.Compare(x.AttackerID, y.AttackerID),
		cmp.Compare(x.Description, y.Description),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
	)
}
