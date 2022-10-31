package build

import "time"

type Vulnerability struct {
	ID          string               `json:"id,omitempty"`
	Title       map[string]string    `json:"title,omitempty"`
	Description map[string]string    `json:"description,omitempty"`
	CVSS        map[string][]CVSS    `json:"cvss,omitempty"`
	EPSS        *EPSS                `json:"epss,omitempty"`
	CWE         map[string][]string  `json:"cwe,omitempty"`
	Published   map[string]time.Time `json:"published,omitempty"`
	Modified    map[string]time.Time `json:"modified,omitempty"`
	References  []Reference          `json:"references,omitempty"`
}

type CVSS struct {
	Version  string
	Source   string
	Vector   string
	Score    *float64
	Severity string
}

type EPSS struct {
	EPSS       *float64 `json:"epss,omitempty"`
	Percentile *float64 `json:"percentile,omitempty"`
}

type Reference struct {
	Source string   `json:"source,omitempty"`
	Name   string   `json:"name,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	URL    string   `json:"url,omitempty"`
}

type DetectCPE struct {
	ID             string             `json:"id,omitempty"`
	Configurations []CPEConfiguration `json:"configurations,omitempty"`
}

type CPEConfiguration struct {
	Vulnerable []CPE `json:"vulnerable,omitempty"`
	RunningOn  []CPE `json:"running_on,omitempty"`
}

type CPE struct {
	Cpe23URI              string  `json:"cpe23Uri,omitempty"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
}
