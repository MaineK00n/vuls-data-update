package advisory

import (
	"cmp"
	"slices"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
)

type Advisory struct {
	ID          string                 `json:"id,omitempty"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	Severity    []severity.Severity    `json:"severity,omitempty"`
	CWE         []cwe.CWE              `json:"cwe,omitempty"`
	References  []reference.Reference  `json:"references,omitempty"`
	Published   *time.Time             `json:"published,omitempty"`
	Modified    *time.Time             `json:"modified,omitempty"`
	Optional    map[string]interface{} `json:"optional,omitempty"`
}

func (a *Advisory) Sort() {
	slices.SortFunc(a.Severity, severity.Compare)

	for i := range a.CWE {
		(&a.CWE[i]).Sort()
	}
	slices.SortFunc(a.CWE, cwe.Compare)

	slices.SortFunc(a.References, reference.Compare)
}

func Compare(x, y Advisory) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Title, y.Title),
		cmp.Compare(x.Description, y.Description),
		slices.CompareFunc(x.Severity, y.Severity, severity.Compare),
		slices.CompareFunc(x.CWE, y.CWE, cwe.Compare),
		slices.CompareFunc(x.References, y.References, reference.Compare),
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
