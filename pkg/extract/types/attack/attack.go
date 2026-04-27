package attack

import (
	"cmp"
	"slices"
	"time"

	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// Kind identifies the ATT&CK object category, derived from the STIX object type.
type Kind string

const (
	KindTechnique       Kind = "technique"         // attack-pattern
	KindTactic          Kind = "tactic"            // x-mitre-tactic
	KindMitigation      Kind = "mitigation"        // course-of-action
	KindDataSource      Kind = "data-source"       // x-mitre-data-source
	KindDataComponent   Kind = "data-component"    // x-mitre-data-component
	KindAnalytic        Kind = "analytic"          // x-mitre-analytic
	KindDetectStrategy  Kind = "detection-strategy" // x-mitre-detection-strategy
	KindAsset           Kind = "asset"             // x-mitre-asset
	KindMatrix          Kind = "matrix"            // x-mitre-matrix
)

// Attack represents a single ATT&CK object keyed by its external_id (e.g. "T1234", "TA0001", "M1050").
// Field relevance depends on Kind — for example Platforms/IsSubtechnique apply only to Techniques.
type Attack struct {
	ID             string                   `json:"id"`
	Kind           Kind                     `json:"kind,omitempty"`
	Name           string                   `json:"name,omitempty"`
	Description    string                   `json:"description,omitempty"`
	Domains        []string                 `json:"domains,omitempty"`   // enterprise / ics / mobile
	Platforms      []string                 `json:"platforms,omitempty"` // Technique only
	Tactics        []string                 `json:"tactics,omitempty"`   // Technique only; tactic shortnames (e.g. "initial-access")
	Shortname      string                   `json:"shortname,omitempty"` // Tactic only
	IsSubtechnique bool                     `json:"is_subtechnique,omitempty"`
	Parent         string                   `json:"parent,omitempty"` // Subtechnique parent Technique ID
	Deprecated     bool                     `json:"deprecated,omitempty"`
	Revoked        bool                     `json:"revoked,omitempty"`
	Version        string                   `json:"version,omitempty"`
	Modified       *time.Time               `json:"modified,omitempty"`
	References     []referenceTypes.Reference `json:"references,omitempty"`
	DataSource     sourceTypes.Source       `json:"data_source,omitzero"`
}

func (a *Attack) Sort() {
	slices.Sort(a.Domains)
	slices.Sort(a.Platforms)
	slices.Sort(a.Tactics)
	slices.SortFunc(a.References, referenceTypes.Compare)
	a.DataSource.Sort()
}

func Compare(x, y Attack) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Kind, y.Kind),
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.Description, y.Description),
		slices.Compare(x.Domains, y.Domains),
		slices.Compare(x.Platforms, y.Platforms),
		slices.Compare(x.Tactics, y.Tactics),
		cmp.Compare(x.Shortname, y.Shortname),
		boolCompare(x.IsSubtechnique, y.IsSubtechnique),
		cmp.Compare(x.Parent, y.Parent),
		boolCompare(x.Deprecated, y.Deprecated),
		boolCompare(x.Revoked, y.Revoked),
		cmp.Compare(x.Version, y.Version),
		timeCompare(x.Modified, y.Modified),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}

func boolCompare(x, y bool) int {
	switch {
	case x == y:
		return 0
	case !x && y:
		return -1
	default:
		return 1
	}
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
