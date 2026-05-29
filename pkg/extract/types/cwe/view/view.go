package view

import (
	"cmp"
	"slices"

	mappingnotesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes"
	memberTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/member"
	noteTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/note"
	audienceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/view/audience"
)

type View struct {
	Type         string                         `json:"type,omitempty"` // "Graph" | "Implicit" | "Slice"
	Audience     []audienceTypes.Audience       `json:"audience,omitempty"`
	Members      []memberTypes.Member           `json:"members,omitempty"`
	Notes        []noteTypes.Note               `json:"notes,omitempty"`
	MappingNotes mappingnotesTypes.MappingNotes `json:"mapping_notes,omitzero"`
}

func (v *View) Sort() {
	slices.SortFunc(v.Audience, audienceTypes.Compare)
	slices.SortFunc(v.Members, memberTypes.Compare)
	slices.SortFunc(v.Notes, noteTypes.Compare)
	v.MappingNotes.Sort()
}

func Compare(x, y View) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		slices.CompareFunc(x.Audience, y.Audience, audienceTypes.Compare),
		slices.CompareFunc(x.Members, y.Members, memberTypes.Compare),
		slices.CompareFunc(x.Notes, y.Notes, noteTypes.Compare),
		mappingnotesTypes.Compare(x.MappingNotes, y.MappingNotes),
	)
}
