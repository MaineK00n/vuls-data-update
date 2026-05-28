package datacomponent

import (
	"cmp"
	"slices"
)

// DataComponent represents the kind-specific fields for an ATT&CK Data
// Component (STIX x-mitre-data-component).
type DataComponent struct {
	DataSource string      `json:"data_source,omitempty"` // DataSource ID ("DS*")
	LogSources []LogSource `json:"log_sources,omitempty"`
}

// LogSource is an embedded entry inside DataComponent.LogSources.
type LogSource struct {
	Name    string `json:"name"`
	Channel string `json:"channel"`
}

func (d *DataComponent) Sort() {
	slices.SortFunc(d.LogSources, CompareLogSource)
}

func Compare(x, y DataComponent) int {
	return cmp.Or(
		cmp.Compare(x.DataSource, y.DataSource),
		slices.CompareFunc(x.LogSources, y.LogSources, CompareLogSource),
	)
}

func CompareLogSource(x, y LogSource) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Channel, y.Channel),
	)
}
