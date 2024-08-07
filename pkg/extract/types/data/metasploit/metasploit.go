package metasploit

import (
	"cmp"
	"slices"
	"time"

	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

type Metasploit struct {
	Type        string                     `json:"type,omitempty"`
	Name        string                     `json:"name,omitempty"`
	FullName    string                     `json:"full_name,omitempty"`
	Description string                     `json:"description,omitempty"`
	Rank        int                        `json:"rank,omitempty"`
	Published   *time.Time                 `json:"published,omitempty"`
	Modified    *time.Time                 `json:"modified,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

func (m *Metasploit) Sort() {
	slices.SortFunc(m.References, referenceTypes.Compare)
}

func Compare(x, y Metasploit) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.Rank, y.Rank),
		cmp.Compare(x.FullName, y.FullName),
	)
}
