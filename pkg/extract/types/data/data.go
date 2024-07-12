package data

import (
	"slices"

	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type Data struct {
	ID              string                             `json:"id,omitempty"`
	Advisories      []advisoryTypes.Advisory           `json:"advisories,omitempty"`
	Vulnerabilities []vulnerabilityTypes.Vulnerability `json:"vulnerabilities,omitempty"`
	Detection       []detectionTypes.Detection         `json:"detection,omitempty"`
	DataSource      sourceTypes.SourceID               `json:"data_source,omitempty"`
}

func (d *Data) Sort() {
	for i := range d.Advisories {
		d.Advisories[i].Sort()
	}
	slices.SortFunc(d.Advisories, advisoryTypes.Compare)

	for i := range d.Vulnerabilities {
		d.Vulnerabilities[i].Sort()
	}
	slices.SortFunc(d.Vulnerabilities, vulnerabilityTypes.Compare)

	for i := range d.Detection {
		d.Detection[i].Sort()
	}
	slices.SortFunc(d.Detection, detectionTypes.Compare)
}
