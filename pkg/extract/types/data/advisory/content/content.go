package content

import (
	"cmp"
	"slices"
	"time"

	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
)

type Content struct {
	ID          string                     `json:"id,omitempty"`
	Title       string                     `json:"title,omitempty"`
	Description string                     `json:"description,omitempty"`
	Severity    []severityTypes.Severity   `json:"severity,omitempty"`
	CWE         []cweTypes.CWE             `json:"cwe,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
	Published   *time.Time                 `json:"published,omitempty"`
	Modified    *time.Time                 `json:"modified,omitempty"`
	Optional    map[string]interface{}     `json:"optional,omitempty"`
}

// FIXME: add packages
func (c *Content) Sort() {
	slices.SortFunc(c.Severity, severityTypes.Compare)

	for i := range c.CWE {
		(&c.CWE[i]).Sort()
	}
	slices.SortFunc(c.CWE, cweTypes.Compare)

	slices.SortFunc(c.References, referenceTypes.Compare)
}

// FIXME: add packages
func Compare(x, y Content) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Title, y.Title),
		cmp.Compare(x.Description, y.Description),
		slices.CompareFunc(x.Severity, y.Severity, severityTypes.Compare),
		slices.CompareFunc(x.CWE, y.CWE, cweTypes.Compare),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
		func() int {
			switch {
			case x.Published == nil && y.Published == nil:
				return 0
			case x.Published == nil && y.Published != nil:
				return -1
			case x.Published != nil && y.Published == nil:
				return +1
			default:
				return (*x.Published).Compare(*y.Published)
			}
		}(),
		func() int {
			switch {
			case x.Modified == nil && y.Modified == nil:
				return 0
			case x.Modified == nil && y.Modified != nil:
				return -1
			case x.Modified != nil && y.Modified == nil:
				return +1
			default:
				return (*x.Modified).Compare(*y.Modified)
			}
		}(),
	)
}
