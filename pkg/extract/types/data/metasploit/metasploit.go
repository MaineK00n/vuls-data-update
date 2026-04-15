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
	Aliases     []string                   `json:"aliases,omitempty"`
	Description string                     `json:"description,omitempty"`
	Rank        int                        `json:"rank,omitempty"`
	Author      []string                   `json:"author,omitempty"`
	Platform    string                     `json:"platform,omitempty"`
	Arch        string                     `json:"arch,omitempty"`
	Targets     []string                   `json:"targets,omitempty"`
	Published   time.Time                  `json:"published,omitzero"`
	Modified    time.Time                  `json:"modified,omitzero"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

func (m *Metasploit) Sort() {
	slices.Sort(m.Aliases)
	slices.Sort(m.Author)
	slices.Sort(m.Targets)
	slices.SortFunc(m.References, referenceTypes.Compare)
}

func Compare(x, y Metasploit) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.Rank, y.Rank),
		cmp.Compare(x.FullName, y.FullName),
	)
}
