package weakness

import (
	"cmp"
	"slices"

	mappingnotesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes"
	noteTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/note"
	taxonomymappingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/taxonomymapping"
	alternatetermTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/alternateterm"
	applicableplatformTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/applicableplatform"
	commonconsequenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/commonconsequence"
	demonstrativeexampleTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/demonstrativeexample"
	detectionmethodTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/detectionmethod"
	modeofintroductionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/modeofintroduction"
	potentialmitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/potentialmitigation"
	rankingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/ranking"
	relatedweaknessTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/relatedweakness"
	weaknessordinalityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/weaknessordinality"
)

type Weakness struct {
	Abstraction           string                                           `json:"abstraction,omitempty"`
	Structure             string                                           `json:"structure,omitempty"`
	Diagram               string                                           `json:"diagram,omitempty"`
	ExtendedDescription   string                                           `json:"extended_description,omitempty"`
	LikelihoodOfExploit   string                                           `json:"likelihood_of_exploit,omitempty"`
	BackgroundDetails     []string                                         `json:"background_details,omitempty"`
	ModesOfIntroduction   []modeofintroductionTypes.ModeOfIntroduction     `json:"modes_of_introduction,omitempty"`
	RelatedWeaknesses     []relatedweaknessTypes.RelatedWeakness           `json:"related_weaknesses,omitempty"`
	RelatedAttackPatterns []string                                         `json:"related_attack_patterns,omitempty"` // "CAPEC-*"
	WeaknessOrdinalities  []weaknessordinalityTypes.WeaknessOrdinality     `json:"weakness_ordinalities,omitempty"`
	ApplicablePlatforms   []applicableplatformTypes.ApplicablePlatform     `json:"applicable_platforms,omitempty"`
	AffectedResources     []string                                         `json:"affected_resources,omitempty"`
	FunctionalAreas       []string                                         `json:"functional_areas,omitempty"`
	AlternateTerms        []alternatetermTypes.AlternateTerm               `json:"alternate_terms,omitempty"`
	CommonConsequences    []commonconsequenceTypes.CommonConsequence       `json:"common_consequences,omitempty"`
	PotentialMitigations  []potentialmitigationTypes.PotentialMitigation   `json:"potential_mitigations,omitempty"`
	DemonstrativeExamples []demonstrativeexampleTypes.DemonstrativeExample `json:"demonstrative_examples,omitempty"`
	DetectionMethods      []detectionmethodTypes.DetectionMethod           `json:"detection_methods,omitempty"`
	TaxonomyMappings      []taxonomymappingTypes.TaxonomyMapping           `json:"taxonomy_mappings,omitempty"`
	Notes                 []noteTypes.Note                                 `json:"notes,omitempty"`
	Rankings              []rankingTypes.Ranking                           `json:"rankings,omitempty"` // CWE Top 25 / OWASP / CWE-SANS placements, derived from ranking lists
	MappingNotes          mappingnotesTypes.MappingNotes                   `json:"mapping_notes,omitzero"`
}

func (w *Weakness) Sort() {
	slices.Sort(w.RelatedAttackPatterns)
	slices.Sort(w.BackgroundDetails)
	slices.Sort(w.AffectedResources)
	slices.Sort(w.FunctionalAreas)
	for i := range w.ModesOfIntroduction {
		(&w.ModesOfIntroduction[i]).Sort()
	}
	slices.SortFunc(w.ModesOfIntroduction, modeofintroductionTypes.Compare)
	slices.SortFunc(w.RelatedWeaknesses, relatedweaknessTypes.Compare)
	slices.SortFunc(w.WeaknessOrdinalities, weaknessordinalityTypes.Compare)
	slices.SortFunc(w.ApplicablePlatforms, applicableplatformTypes.Compare)
	slices.SortFunc(w.AlternateTerms, alternatetermTypes.Compare)
	for i := range w.CommonConsequences {
		(&w.CommonConsequences[i]).Sort()
	}
	slices.SortFunc(w.CommonConsequences, commonconsequenceTypes.Compare)
	for i := range w.PotentialMitigations {
		(&w.PotentialMitigations[i]).Sort()
	}
	slices.SortFunc(w.PotentialMitigations, potentialmitigationTypes.Compare)
	slices.SortFunc(w.DemonstrativeExamples, demonstrativeexampleTypes.Compare)
	slices.SortFunc(w.DetectionMethods, detectionmethodTypes.Compare)
	slices.SortFunc(w.TaxonomyMappings, taxonomymappingTypes.Compare)
	slices.SortFunc(w.Notes, noteTypes.Compare)
	slices.SortFunc(w.Rankings, rankingTypes.Compare)
	w.MappingNotes.Sort()
}

func Compare(x, y Weakness) int {
	return cmp.Or(
		cmp.Compare(x.Abstraction, y.Abstraction),
		cmp.Compare(x.Structure, y.Structure),
		cmp.Compare(x.Diagram, y.Diagram),
		cmp.Compare(x.ExtendedDescription, y.ExtendedDescription),
		cmp.Compare(x.LikelihoodOfExploit, y.LikelihoodOfExploit),
		slices.Compare(x.BackgroundDetails, y.BackgroundDetails),
		slices.CompareFunc(x.ModesOfIntroduction, y.ModesOfIntroduction, modeofintroductionTypes.Compare),
		slices.CompareFunc(x.RelatedWeaknesses, y.RelatedWeaknesses, relatedweaknessTypes.Compare),
		slices.Compare(x.RelatedAttackPatterns, y.RelatedAttackPatterns),
		slices.CompareFunc(x.WeaknessOrdinalities, y.WeaknessOrdinalities, weaknessordinalityTypes.Compare),
		slices.CompareFunc(x.ApplicablePlatforms, y.ApplicablePlatforms, applicableplatformTypes.Compare),
		slices.Compare(x.AffectedResources, y.AffectedResources),
		slices.Compare(x.FunctionalAreas, y.FunctionalAreas),
		slices.CompareFunc(x.AlternateTerms, y.AlternateTerms, alternatetermTypes.Compare),
		slices.CompareFunc(x.CommonConsequences, y.CommonConsequences, commonconsequenceTypes.Compare),
		slices.CompareFunc(x.PotentialMitigations, y.PotentialMitigations, potentialmitigationTypes.Compare),
		slices.CompareFunc(x.DemonstrativeExamples, y.DemonstrativeExamples, demonstrativeexampleTypes.Compare),
		slices.CompareFunc(x.DetectionMethods, y.DetectionMethods, detectionmethodTypes.Compare),
		slices.CompareFunc(x.TaxonomyMappings, y.TaxonomyMappings, taxonomymappingTypes.Compare),
		slices.CompareFunc(x.Notes, y.Notes, noteTypes.Compare),
		slices.CompareFunc(x.Rankings, y.Rankings, rankingTypes.Compare),
		mappingnotesTypes.Compare(x.MappingNotes, y.MappingNotes),
	)
}
