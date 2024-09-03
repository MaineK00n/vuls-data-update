package data

import (
	"cmp"
	"slices"

	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type Data struct {
	ID              string                             `json:"id,omitempty"`
	Advisories      []advisoryTypes.Advisory           `json:"advisories,omitempty"`
	Vulnerabilities []vulnerabilityTypes.Vulnerability `json:"vulnerabilities,omitempty"`
	Detection       []detectionTypes.Detection         `json:"detection,omitempty"`
	DataSource      sourceTypes.Source                 `json:"data_source,omitempty"`
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

	d.DataSource.Sort()
}

func Compare(x, y Data) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		slices.CompareFunc(x.Advisories, y.Advisories, advisoryTypes.Compare),
		slices.CompareFunc(x.Vulnerabilities, y.Vulnerabilities, vulnerabilityTypes.Compare),
		slices.CompareFunc(x.Detection, y.Detection, detectionTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}

func (d *Data) Merge(ds ...Data) {
	for _, e := range ds {
		if d.ID != e.ID {
			continue
		}

		as := d.Advisories
		for i, da := range d.Advisories {
			for _, ea := range e.Advisories {
				switch advisoryContentTypes.Compare(da.Content, ea.Content) {
				case 0:
					as[i] = advisoryTypes.Advisory{
						Content:    da.Content,
						Ecosystems: append(da.Ecosystems, ea.Ecosystems...),
					}
				default:
					as = append(as, ea)
				}
			}
		}

		vs := d.Vulnerabilities
		for i, dv := range d.Vulnerabilities {
			for _, ev := range e.Vulnerabilities {
				switch vulnerabilityContentTypes.Compare(dv.Content, ev.Content) {
				case 0:
					vs[i] = vulnerabilityTypes.Vulnerability{
						Content:    dv.Content,
						Ecosystems: append(dv.Ecosystems, ev.Ecosystems...),
					}
				default:
					vs = append(vs, ev)
				}
			}
		}

		d.Detection = append(d.Detection, e.Detection...)

		for _, r := range e.DataSource.Raws {
			if !slices.Contains(d.DataSource.Raws, r) {
				d.DataSource.Raws = append(d.DataSource.Raws, r)
			}
		}
	}
}
