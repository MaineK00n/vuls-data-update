package cwe

import (
	"cmp"
	"slices"

	relatedweaknessTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/relatedweakness"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// CWE represents a CWE weakness (MITRE CWE data) keyed by its ID in "CWE-*" form.
// Categories and Views share the same envelope with Kind distinguishing them.
type CWE struct {
	ID                    string                                  `json:"id"`
	Kind                  string                                  `json:"kind,omitempty"` // "weakness" | "category" | "view"
	Name                  string                                  `json:"name,omitempty"`
	Abstraction           string                                  `json:"abstraction,omitempty"`
	Structure             string                                  `json:"structure,omitempty"`
	Status                string                                  `json:"status,omitempty"`
	Description           string                                  `json:"description,omitempty"`
	ExtendedDescription   string                                  `json:"extended_description,omitempty"`
	ModesOfIntroduction   []string                                `json:"modes_of_introduction,omitempty"` // Phase names only
	LikelihoodOfExploit   string                                  `json:"likelihood_of_exploit,omitempty"`
	RelatedWeaknesses     []relatedweaknessTypes.RelatedWeakness  `json:"related_weaknesses,omitempty"`
	RelatedAttackPatterns []string                                `json:"related_attack_patterns,omitempty"` // "CAPEC-*"
	Platforms             []string                                `json:"platforms,omitempty"`
	References            []referenceTypes.Reference              `json:"references,omitempty"`
	DataSource            sourceTypes.Source                      `json:"data_source,omitzero"`
}

func (c *CWE) Sort() {
	slices.Sort(c.ModesOfIntroduction)
	slices.Sort(c.RelatedAttackPatterns)
	slices.Sort(c.Platforms)
	slices.SortFunc(c.RelatedWeaknesses, relatedweaknessTypes.Compare)
	slices.SortFunc(c.References, referenceTypes.Compare)
	c.DataSource.Sort()
}

func Compare(x, y CWE) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Kind, y.Kind),
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Abstraction, y.Abstraction),
		cmp.Compare(x.Structure, y.Structure),
		cmp.Compare(x.Status, y.Status),
		cmp.Compare(x.Description, y.Description),
		cmp.Compare(x.LikelihoodOfExploit, y.LikelihoodOfExploit),
		slices.Compare(x.ModesOfIntroduction, y.ModesOfIntroduction),
		slices.Compare(x.RelatedAttackPatterns, y.RelatedAttackPatterns),
		slices.Compare(x.Platforms, y.Platforms),
		slices.CompareFunc(x.RelatedWeaknesses, y.RelatedWeaknesses, relatedweaknessTypes.Compare),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}
