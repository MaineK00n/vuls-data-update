// Package kind exposes the ATT&CK Kind enum on its own so leaf
// sub-types (e.g., attack/procedure) can carry a typed Kind field
// without creating an import cycle back to pkg/extract/types/attack.
//
// The root attack package re-exports both the Kind type and its
// constants via aliases, so existing call sites keep referring to
// attackTypes.Kind* unchanged.
package kind

// Kind identifies the ATT&CK object category, derived from the STIX
// object type.
type Kind string

const (
	Technique      Kind = "technique"          // attack-pattern
	Tactic         Kind = "tactic"             // x-mitre-tactic
	Mitigation     Kind = "mitigation"         // course-of-action
	Group          Kind = "group"              // intrusion-set
	Software       Kind = "software"           // malware | tool
	Campaign       Kind = "campaign"           // campaign
	DataSource     Kind = "data-source"        // x-mitre-data-source
	DataComponent  Kind = "data-component"     // x-mitre-data-component
	Analytic       Kind = "analytic"           // x-mitre-analytic
	DetectStrategy Kind = "detection-strategy" // x-mitre-detection-strategy
	Asset          Kind = "asset"              // x-mitre-asset
)
