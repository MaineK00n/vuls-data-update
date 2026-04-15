package enisa

import (
	"cmp"
	"time"
)

type ENISA struct {
	DateReported           time.Time `json:"date_reported,omitzero"`
	PatchedSince           string    `json:"patched_since,omitempty"`
	OriginSource           string    `json:"origin_source,omitempty"`
	ExploitationType       string    `json:"exploitation_type,omitempty"`
	ThreatActorsExploiting string    `json:"threat_actors_exploiting,omitempty"`
}

func Compare(x, y ENISA) int {
	return cmp.Or(
		x.DateReported.Compare(y.DateReported),
		cmp.Compare(x.PatchedSince, y.PatchedSince),
		cmp.Compare(x.OriginSource, y.OriginSource),
		cmp.Compare(x.ExploitationType, y.ExploitationType),
		cmp.Compare(x.ThreatActorsExploiting, y.ThreatActorsExploiting),
	)
}
