package attack

import (
	"cmp"
	"slices"
	"time"

	campaignTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/campaign"
	groupTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/group"
	softwareTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/software"
	tacticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/tactic"
	techniqueTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/technique"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// Kind identifies the ATT&CK object category, derived from the STIX object type.
type Kind string

const (
	KindTechnique      Kind = "technique"          // attack-pattern
	KindTactic         Kind = "tactic"             // x-mitre-tactic
	KindMitigation     Kind = "mitigation"         // course-of-action
	KindGroup          Kind = "group"              // intrusion-set
	KindSoftware       Kind = "software"           // malware | tool
	KindCampaign       Kind = "campaign"           // campaign
	KindDataSource     Kind = "data-source"        // x-mitre-data-source
	KindDataComponent  Kind = "data-component"     // x-mitre-data-component
	KindAnalytic       Kind = "analytic"           // x-mitre-analytic
	KindDetectStrategy Kind = "detection-strategy" // x-mitre-detection-strategy
	KindAsset          Kind = "asset"              // x-mitre-asset
	KindMatrix         Kind = "matrix"             // x-mitre-matrix
)

// Attack represents a single ATT&CK object keyed by its external_id (e.g. "T1234", "TA0001", "M1050").
// Kind-specific fields are grouped in nested types: Technique, Tactic.
type Attack struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind,omitempty"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Domains     []string  `json:"domains,omitempty"` // enterprise / ics / mobile
	Deprecated  bool      `json:"deprecated,omitempty"`
	Revoked     bool      `json:"revoked,omitempty"`
	Version     string    `json:"version,omitempty"`
	Modified    time.Time `json:"modified,omitzero"`

	Technique techniqueTypes.Technique `json:"technique,omitzero"`
	Tactic    tacticTypes.Tactic       `json:"tactic,omitzero"`
	Group     groupTypes.Group         `json:"group,omitzero"`
	Software  softwareTypes.Software   `json:"software,omitzero"`
	Campaign  campaignTypes.Campaign   `json:"campaign,omitzero"`

	References []referenceTypes.Reference `json:"references,omitempty"`
	DataSource sourceTypes.Source         `json:"data_source,omitzero"`
}

func (a *Attack) Sort() {
	slices.Sort(a.Domains)
	a.Technique.Sort()
	a.Group.Sort()
	a.Software.Sort()
	a.Campaign.Sort()
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
		techniqueTypes.Compare(x.Technique, y.Technique),
		tacticTypes.Compare(x.Tactic, y.Tactic),
		groupTypes.Compare(x.Group, y.Group),
		softwareTypes.Compare(x.Software, y.Software),
		campaignTypes.Compare(x.Campaign, y.Campaign),
		cmp.Compare(x.Version, y.Version),
		x.Modified.Compare(y.Modified),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}
