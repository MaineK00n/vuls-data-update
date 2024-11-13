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
	ID              RootID                             `json:"id,omitempty"`
	Advisories      []advisoryTypes.Advisory           `json:"advisories,omitempty"`
	Vulnerabilities []vulnerabilityTypes.Vulnerability `json:"vulnerabilities,omitempty"`
	Detections      []detectionTypes.Detection         `json:"detections,omitempty"`
	DataSource      sourceTypes.Source                 `json:"data_source,omitempty"`
}

type RootID string

func (d *Data) Sort() {
	for i := range d.Advisories {
		d.Advisories[i].Sort()
	}
	slices.SortFunc(d.Advisories, advisoryTypes.Compare)

	for i := range d.Vulnerabilities {
		d.Vulnerabilities[i].Sort()
	}
	slices.SortFunc(d.Vulnerabilities, vulnerabilityTypes.Compare)

	for i := range d.Detections {
		d.Detections[i].Sort()
	}
	slices.SortFunc(d.Detections, detectionTypes.Compare)

	d.DataSource.Sort()
}

func Compare(x, y Data) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		slices.CompareFunc(x.Advisories, y.Advisories, advisoryTypes.Compare),
		slices.CompareFunc(x.Vulnerabilities, y.Vulnerabilities, vulnerabilityTypes.Compare),
		slices.CompareFunc(x.Detections, y.Detections, detectionTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}

func (d *Data) Merge(ds ...Data) {
	for _, e := range ds {
		if d.ID != e.ID {
			continue
		}

		as := d.Advisories
		for _, ea := range e.Advisories {
			i := slices.IndexFunc(as, func(a advisoryTypes.Advisory) bool {
				return advisoryContentTypes.Compare(a.Content, ea.Content) == 0
			})
			switch {
			case i < 0:
				as = append(as, ea)
			default:
				as[i] = advisoryTypes.Advisory{
					Content:  as[i].Content,
					Segments: append(as[i].Segments, ea.Segments...),
				}
			}
		}
		d.Advisories = as

		vs := d.Vulnerabilities
		for _, ev := range e.Vulnerabilities {
			i := slices.IndexFunc(vs, func(v vulnerabilityTypes.Vulnerability) bool {
				return vulnerabilityContentTypes.Compare(v.Content, ev.Content) == 0
			})
			switch {
			case i < 0:
				vs = append(vs, ev)
			default:
				vs[i] = vulnerabilityTypes.Vulnerability{
					Content:  vs[i].Content,
					Segments: append(vs[i].Segments, ev.Segments...),
				}
			}
		}
		d.Vulnerabilities = vs

		ds := d.Detections
		for _, ed := range e.Detections {
			i := slices.IndexFunc(ds, func(d detectionTypes.Detection) bool {
				return d.Ecosystem == ed.Ecosystem
			})
			switch {
			case i < 0:
				ds = append(ds, ed)
			default:
				ds[i].Conditions = append(ds[i].Conditions, ed.Conditions...)
			}
		}
		d.Detections = ds

		for _, r := range e.DataSource.Raws {
			if !slices.Contains(d.DataSource.Raws, r) {
				d.DataSource.Raws = append(d.DataSource.Raws, r)
			}
		}
	}
}
