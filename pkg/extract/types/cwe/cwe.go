package cwe

import (
	"cmp"
	"slices"

	categoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/category"
	viewTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/view"
	weaknessTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// CWE represents an entry from the MITRE CWE catalog keyed by its ID in
// "CWE-*" form. Kind distinguishes weakness / category / view; kind-specific
// fields live in nested sub-structs.
type CWE struct {
	ID          string `json:"id"`
	Kind        string `json:"kind,omitempty"` // "weakness" | "category" | "view"
	Name        string `json:"name,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"` // main text (Weakness.Description / Category.Summary / View.Objective)

	Weakness weaknessTypes.Weakness `json:"weakness,omitzero"`
	Category categoryTypes.Category `json:"category,omitzero"`
	View     viewTypes.View         `json:"view,omitzero"`

	References []referenceTypes.Reference `json:"references,omitempty"`
	DataSource sourceTypes.Source         `json:"data_source,omitzero"`
}

func (c *CWE) Sort() {
	c.Weakness.Sort()
	c.Category.Sort()
	c.View.Sort()
	slices.SortFunc(c.References, referenceTypes.Compare)
	c.DataSource.Sort()
}

func Compare(x, y CWE) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Kind, y.Kind),
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Status, y.Status),
		cmp.Compare(x.Description, y.Description),
		weaknessTypes.Compare(x.Weakness, y.Weakness),
		categoryTypes.Compare(x.Category, y.Category),
		viewTypes.Compare(x.View, y.View),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}
