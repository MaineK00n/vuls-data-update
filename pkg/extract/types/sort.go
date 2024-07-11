package types

import (
	"slices"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/advisory"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/vulnerability"
)

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

func (d *CPEDictionary) Sort() {}

func (d *CWEDictionary) Sort() {}

func (d *CAPECDictionary) Sort() {}

func (d *AttackDictionary) Sort() {}

func (d *WindowsKBDictionary) Sort() {}

func (d *EOLDictionary) Sort() {}
