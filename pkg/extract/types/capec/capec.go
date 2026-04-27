package capec

import (
	"cmp"
	"slices"
	"time"

	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// CAPEC represents a CAPEC attack pattern (from MITRE/CTI STIX data)
// keyed by its external_id (e.g. "CAPEC-66").
type CAPEC struct {
	ID                  string                     `json:"id"`
	Name                string                     `json:"name,omitempty"`
	Description         string                     `json:"description,omitempty"`
	ExtendedDescription string                     `json:"extended_description,omitempty"`
	Abstraction         string                     `json:"abstraction,omitempty"`
	Status              string                     `json:"status,omitempty"`
	LikelihoodOfAttack  string                     `json:"likelihood_of_attack,omitempty"`
	TypicalSeverity     string                     `json:"typical_severity,omitempty"`
	Domains             []string                   `json:"domains,omitempty"`
	Prerequisites       []string                   `json:"prerequisites,omitempty"`
	SkillsRequired      map[string]string          `json:"skills_required,omitempty"` // keyed by level (High/Medium/Low)
	ResourcesRequired   []string                   `json:"resources_required,omitempty"`
	Consequences        map[string][]string        `json:"consequences,omitempty"`
	RelatedCWEs         []string                   `json:"related_cwes,omitempty"`    // "CWE-*"
	RelatedAttacks      []string                   `json:"related_attacks,omitempty"` // ATT&CK Technique IDs ("T*")
	ChildOf             []string                   `json:"child_of,omitempty"`        // "CAPEC-*"
	ParentOf            []string                   `json:"parent_of,omitempty"`
	CanFollow           []string                   `json:"can_follow,omitempty"`
	CanPrecede          []string                   `json:"can_precede,omitempty"`
	PeerOf              []string                   `json:"peer_of,omitempty"`
	AlternateTerms      []string                   `json:"alternate_terms,omitempty"`
	Version             string                     `json:"version,omitempty"`
	Modified            *time.Time                 `json:"modified,omitempty"`
	References          []referenceTypes.Reference `json:"references,omitempty"`
	DataSource          sourceTypes.Source         `json:"data_source,omitzero"`
}

func (c *CAPEC) Sort() {
	slices.Sort(c.Domains)
	slices.Sort(c.Prerequisites)
	slices.Sort(c.ResourcesRequired)
	slices.Sort(c.RelatedCWEs)
	slices.Sort(c.RelatedAttacks)
	slices.Sort(c.ChildOf)
	slices.Sort(c.ParentOf)
	slices.Sort(c.CanFollow)
	slices.Sort(c.CanPrecede)
	slices.Sort(c.PeerOf)
	slices.Sort(c.AlternateTerms)
	for k := range c.Consequences {
		slices.Sort(c.Consequences[k])
	}
	slices.SortFunc(c.References, referenceTypes.Compare)
	c.DataSource.Sort()
}

func Compare(x, y CAPEC) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Description, y.Description),
		cmp.Compare(x.Abstraction, y.Abstraction),
		cmp.Compare(x.Status, y.Status),
		slices.Compare(x.Domains, y.Domains),
		slices.Compare(x.RelatedCWEs, y.RelatedCWEs),
		slices.Compare(x.RelatedAttacks, y.RelatedAttacks),
		slices.Compare(x.ChildOf, y.ChildOf),
		slices.Compare(x.ParentOf, y.ParentOf),
		cmp.Compare(x.Version, y.Version),
		timeCompare(x.Modified, y.Modified),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}

func timeCompare(x, y *time.Time) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -1
	case y == nil:
		return 1
	default:
		return x.Compare(*y)
	}
}
