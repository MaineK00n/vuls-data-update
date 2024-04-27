package types

import (
	"slices"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/advisory"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/vulnerability"
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

type CPEDictionary struct{}

type CWEDictionary struct{}

type CAPECDictionary struct{}

type AttackDictionary struct{}

type EOLDictionary struct {
	Ended bool                  `json:"ended"`
	Date  map[string]*time.Time `json:"date,omitempty"`
}
