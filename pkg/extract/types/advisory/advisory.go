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
	if c := cmp.Compare(x.ID, y.ID); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Title, y.Title); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Description, y.Description); c != 0 {
		return c
	}
	if c := slices.CompareFunc(x.Severity, y.Severity, severity.Compare); c != 0 {
		return c
	}
	if c := slices.CompareFunc(x.CWE, y.CWE, cwe.Compare); c != 0 {
		return c
	}
	if c := slices.CompareFunc(x.References, y.References, reference.Compare); c != 0 {
		return c
	}
	if x.Published != nil && y.Published != nil {
		if c := (*x.Published).Compare(*y.Published); c != 0 {
			return c
		}
	}
	if x.Modified != nil && y.Modified != nil {
		if c := (*x.Modified).Compare(*y.Modified); c != 0 {
			return c
		}
	}
	return 0
}
