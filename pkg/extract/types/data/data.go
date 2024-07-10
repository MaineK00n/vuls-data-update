package data

import (
	"slices"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type Data struct {
	ID              string                        `json:"id,omitempty"`
	Advisories      []advisory.Advisory           `json:"advisories,omitempty"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulnerabilities,omitempty"`
	Detection       []detection.Detection         `json:"detection,omitempty"`
	DataSource      source.SourceID               `json:"data_source,omitempty"`
}

func (d *Data) Sort() {
	for i := range d.Advisories {
		(&d.Advisories[i]).Sort()
	}
	slices.SortFunc(d.Advisories, advisory.Compare)

	for i := range d.Vulnerabilities {
		(&d.Vulnerabilities[i]).Sort()
	}
	slices.SortFunc(d.Vulnerabilities, vulnerability.Compare)

}
