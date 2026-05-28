package datasource

import (
	"cmp"
	"slices"
)

// DataSource represents the kind-specific fields for an ATT&CK Data Source
// (STIX x-mitre-data-source).
type DataSource struct {
	Platforms        []string `json:"platforms,omitempty"`
	CollectionLayers []string `json:"collection_layers,omitempty"`
	DataComponents   []string `json:"data_components,omitempty"` // DataComponent IDs ("DC*")
}

func (d *DataSource) Sort() {
	slices.Sort(d.Platforms)
	slices.Sort(d.CollectionLayers)
	slices.Sort(d.DataComponents)
}

func Compare(x, y DataSource) int {
	return cmp.Or(
		slices.Compare(x.Platforms, y.Platforms),
		slices.Compare(x.CollectionLayers, y.CollectionLayers),
		slices.Compare(x.DataComponents, y.DataComponents),
	)
}
