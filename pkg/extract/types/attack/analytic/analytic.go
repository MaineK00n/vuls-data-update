package analytic

import (
	"cmp"
	"slices"
)

// Analytic represents the kind-specific fields for an ATT&CK Analytic
// (STIX x-mitre-analytic).
type Analytic struct {
	DetectionStrategy   string               `json:"detection_strategy,omitempty"` // DetectionStrategy ID ("DET*") that owns this analytic (reverse of detection_strategy.Analytics)
	Platforms           []string             `json:"platforms,omitempty"`
	LogSourceReferences []LogSourceReference `json:"log_source_references,omitempty"`
	MutableElements     []MutableElement     `json:"mutable_elements,omitempty"`
}

// LogSourceReference is an embedded entry inside Analytic.LogSourceReferences.
type LogSourceReference struct {
	DataComponent string `json:"data_component"` // DataComponent ID ("DC*")
	Name          string `json:"name"`
	Channel       string `json:"channel"`
}

// MutableElement is an embedded entry inside Analytic.MutableElements.
type MutableElement struct {
	Field       string `json:"field"`
	Description string `json:"description"`
}

func (a *Analytic) Sort() {
	slices.Sort(a.Platforms)
	slices.SortFunc(a.LogSourceReferences, CompareLogSourceReference)
	slices.SortFunc(a.MutableElements, CompareMutableElement)
}

func Compare(x, y Analytic) int {
	return cmp.Or(
		cmp.Compare(x.DetectionStrategy, y.DetectionStrategy),
		slices.Compare(x.Platforms, y.Platforms),
		slices.CompareFunc(x.LogSourceReferences, y.LogSourceReferences, CompareLogSourceReference),
		slices.CompareFunc(x.MutableElements, y.MutableElements, CompareMutableElement),
	)
}

func CompareLogSourceReference(x, y LogSourceReference) int {
	return cmp.Or(
		cmp.Compare(x.DataComponent, y.DataComponent),
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Channel, y.Channel),
	)
}

func CompareMutableElement(x, y MutableElement) int {
	return cmp.Or(
		cmp.Compare(x.Field, y.Field),
		cmp.Compare(x.Description, y.Description),
	)
}
