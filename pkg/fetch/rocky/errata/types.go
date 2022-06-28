package errata

import "time"

type advisories struct {
	Advisories  []Advisory `json:"advisories"`
	LastUpdated time.Time  `json:"lastUpdated"`
	Page        int        `json:"page"`
	Size        int        `json:"size"`
	Total       int        `json:"total"`
}

type Advisory struct {
	AffectedProducts []string `json:"affectedProducts,omitempty"`
	BuildReferences  []any    `json:"buildReferences,omitempty"`
	Cves             []struct {
		Cvss3BaseScore     string `json:"cvss3BaseScore,omitempty"`
		Cvss3ScoringVector string `json:"cvss3ScoringVector,omitempty"`
		Cwe                string `json:"cwe,omitempty"`
		Name               string `json:"name,omitempty"`
		SourceBy           string `json:"sourceBy,omitempty"`
		SourceLink         string `json:"sourceLink,omitempty"`
	} `json:"cves,omitempty"`
	Description string `json:"description,omitempty"`
	Fixes       []struct {
		Description string `json:"description,omitempty"`
		SourceBy    string `json:"sourceBy,omitempty"`
		SourceLink  string `json:"sourceLink,omitempty"`
		Ticket      string `json:"ticket,omitempty"`
	} `json:"fixes,omitempty"`
	Name            string    `json:"name,omitempty"`
	PublishedAt     time.Time `json:"publishedAt,omitempty"`
	RebootSuggested bool      `json:"rebootSuggested,omitempty"`
	References      []any     `json:"references,omitempty"`
	Rpms            map[string]struct {
		NVRAS []string `json:"nvras,omitempty"`
	} `json:"rpms,omitempty"`
	Severity  string `json:"severity,omitempty"`
	ShortCode string `json:"shortCode,omitempty"`
	Solution  any    `json:"solution,omitempty"`
	Synopsis  string `json:"synopsis,omitempty"`
	Topic     string `json:"topic,omitempty"`
	Type      string `json:"type,omitempty"`
}
