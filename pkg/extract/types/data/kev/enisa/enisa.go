package enisa

import (
	"cmp"
	"slices"
	"time"
)

type ENISA struct {
	DateReported time.Time `json:"date_reported,omitzero"`
	PatchedSince string    `json:"patched_since,omitempty"`
	OriginSource string    `json:"origin_source,omitempty"`
	// Deprecated: Use ExploitationTypes. It holds the same values joined with ", " in the upstream order, whereas ExploitationTypes is sorted.
	ExploitationType string `json:"exploitation_type,omitempty"`
	// Deprecated: Use ThreatActors. It holds the same values joined with ", " in the upstream order, whereas ThreatActors is sorted.
	ThreatActorsExploiting string   `json:"threat_actors_exploiting,omitempty"`
	ExploitationTypes      []string `json:"exploitation_types,omitempty"`
	ThreatActors           []string `json:"threat_actors,omitempty"`
}

func (e *ENISA) Sort() {
	slices.Sort(e.ExploitationTypes)
	slices.Sort(e.ThreatActors)
}

func Compare(x, y ENISA) int {
	return cmp.Or(
		x.DateReported.Compare(y.DateReported),
		cmp.Compare(x.PatchedSince, y.PatchedSince),
		cmp.Compare(x.OriginSource, y.OriginSource),
		cmp.Compare(x.ExploitationType, y.ExploitationType),
		cmp.Compare(x.ThreatActorsExploiting, y.ThreatActorsExploiting),
		slices.Compare(x.ExploitationTypes, y.ExploitationTypes),
		slices.Compare(x.ThreatActors, y.ThreatActors),
	)
}
