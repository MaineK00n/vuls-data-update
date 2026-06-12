package attack

import (
	"cmp"
	"slices"
	"time"

	analyticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/analytic"
	assetTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/asset"
	campaignTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/campaign"
	datacomponentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/datacomponent"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/datasource"
	detectionstrategyTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/detectionstrategy"
	groupTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/group"
	mitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/mitigation"
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
)

// Attack represents a single ATT&CK object keyed by its external_id
// (e.g. "T1234", "TA0001", "M1050", "A0007", "DET0237", "DS0014",
// "DC0084", "AN0110"). Kind-specific fields are grouped in nested
// sub-types; only the one matching Kind is populated.
//
// Note: the ATT&CK Data Source kind's nested struct is exposed as
// AttackDataSource / json "attack_data_source" because the field name
// "DataSource" / json "data_source" is reserved for the per-record
// provenance metadata shared across all extract types.
type Attack struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind,omitempty"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Domains     []string  `json:"domains,omitempty"` // enterprise / ics / mobile
	Deprecated  bool      `json:"deprecated,omitempty"`
	Revoked     bool      `json:"revoked,omitempty"`
	RevokedBy   []string  `json:"revoked_by,omitempty"` // ext-IDs of the replacement(s) when Revoked, sourced from STIX revoked-by relationships; usually one but a split (e.g. one Technique into several) can produce more
	Version     string    `json:"version,omitempty"`
	Created     time.Time `json:"created,omitzero"`
	Modified    time.Time `json:"modified,omitzero"`

	Technique         techniqueTypes.Technique                 `json:"technique,omitzero"`
	Tactic            tacticTypes.Tactic                       `json:"tactic,omitzero"`
	Mitigation        mitigationTypes.Mitigation               `json:"mitigation,omitzero"`
	Group             groupTypes.Group                         `json:"group,omitzero"`
	Software          softwareTypes.Software                   `json:"software,omitzero"`
	Campaign          campaignTypes.Campaign                   `json:"campaign,omitzero"`
	Asset             assetTypes.Asset                         `json:"asset,omitzero"`
	DetectionStrategy detectionstrategyTypes.DetectionStrategy `json:"detection_strategy,omitzero"`
	AttackDataSource  datasourceTypes.DataSource               `json:"attack_data_source,omitzero"`
	DataComponent     datacomponentTypes.DataComponent         `json:"data_component,omitzero"`
	Analytic          analyticTypes.Analytic                   `json:"analytic,omitzero"`

	References []referenceTypes.Reference `json:"references,omitempty"`
	DataSource sourceTypes.Source         `json:"data_source,omitzero"`
}

func (a *Attack) Sort() {
	slices.Sort(a.Domains)
	slices.Sort(a.RevokedBy)
	a.Technique.Sort()
	a.Tactic.Sort()
	a.Mitigation.Sort()
	a.Group.Sort()
	a.Software.Sort()
	a.Campaign.Sort()
	a.Asset.Sort()
	a.DetectionStrategy.Sort()
	a.AttackDataSource.Sort()
	a.DataComponent.Sort()
	a.Analytic.Sort()
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
		func() int {
			switch {
			case !x.Deprecated && y.Deprecated:
				return -1
			case x.Deprecated && !y.Deprecated:
				return +1
			default:
				return 0
			}
		}(),
		func() int {
			switch {
			case !x.Revoked && y.Revoked:
				return -1
			case x.Revoked && !y.Revoked:
				return +1
			default:
				return 0
			}
		}(),
		slices.Compare(x.RevokedBy, y.RevokedBy),
		techniqueTypes.Compare(x.Technique, y.Technique),
		tacticTypes.Compare(x.Tactic, y.Tactic),
		mitigationTypes.Compare(x.Mitigation, y.Mitigation),
		groupTypes.Compare(x.Group, y.Group),
		softwareTypes.Compare(x.Software, y.Software),
		campaignTypes.Compare(x.Campaign, y.Campaign),
		assetTypes.Compare(x.Asset, y.Asset),
		detectionstrategyTypes.Compare(x.DetectionStrategy, y.DetectionStrategy),
		datasourceTypes.Compare(x.AttackDataSource, y.AttackDataSource),
		datacomponentTypes.Compare(x.DataComponent, y.DataComponent),
		analyticTypes.Compare(x.Analytic, y.Analytic),
		cmp.Compare(x.Version, y.Version),
		x.Created.Compare(y.Created),
		x.Modified.Compare(y.Modified),
		slices.CompareFunc(x.References, y.References, referenceTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}
