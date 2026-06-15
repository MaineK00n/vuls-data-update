package procedure

import (
	"cmp"
	"slices"

	kindTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/kind"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

// Procedure pairs a use-relationship's attacker side (an
// intrusion-set / malware / tool / campaign) with the per-edge
// description and citations from the STIX relationship object. The
// attacker can be one of three Kinds (Group / Software / Campaign) —
// unlike every other ATT&CK cross-ref field where the Kind is fixed
// by the enclosing field's name — so AttackerKind is carried inline
// to disambiguate without re-deriving it from the AttackerID prefix.
type Procedure struct {
	AttackerKind kindTypes.Kind             `json:"attacker_kind,omitempty"`
	AttackerID   string                     `json:"attacker_id"`
	Description  string                     `json:"description,omitempty"`
	References   []referenceTypes.Reference `json:"references,omitempty"` // per-edge citations from STIX relationship.external_references
}

func (p *Procedure) Sort() {
	slices.SortFunc(p.References, referenceTypes.Compare)
}

func Compare(x, y Procedure) int {
	return cmp.Or(
		cmp.Compare(x.AttackerKind, y.AttackerKind),
		cmp.Compare(x.AttackerID, y.AttackerID),
		cmp.Compare(x.Description, y.Description),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
	)
}
