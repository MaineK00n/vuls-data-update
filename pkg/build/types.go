package build

import "time"

type Vulnerability struct {
	ID          string               `json:"id,omitempty"`
	Title       map[string]string    `json:"title,omitempty"`
	Description map[string]string    `json:"description,omitempty"`
	CVSS        map[string][]CVSS    `json:"cvss,omitempty"`
	EPSS        *EPSS                `json:"epss,omitempty"`
	CWE         map[string][]string  `json:"cwe,omitempty"`
	Metasploit  []Metasploit         `json:"metasploit,omitempty"`
	Exploit     *Exploit             `json:"exploit,omitempty"`
	KEV         *KEV                 `json:"kev,omitempty"`
	Published   map[string]time.Time `json:"published,omitempty"`
	Modified    map[string]time.Time `json:"modified,omitempty"`
	References  []Reference          `json:"references,omitempty"`
}

type CVSS struct {
	Version  string   `json:"version,omitempty"`
	Source   string   `json:"source,omitempty"`
	Vector   string   `json:"vector,omitempty"`
	Score    *float64 `json:"score,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

type EPSS struct {
	EPSS       *float64 `json:"epss,omitempty"`
	Percentile *float64 `json:"percentile,omitempty"`
}

type Metasploit struct {
	Name        string   `json:"name,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	URLs        []string `json:"urls,omitempty"`
}

type Exploit struct {
	NVD       []string    `json:"nvd,omitempty"`
	ExploitDB []ExploitDB `json:"exploit_db,omitempty"`
	GitHub    []GitHub    `json:"github,omitempty"`
	InTheWild []InTheWild `json:"inthewild,omitempty"`
	Trickest  *Trickest   `json:"trickest,omitempty"`
}

type ExploitDB struct {
	ID          string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	FileURL     string `json:"file_url,omitempty"`
}

type GitHub struct {
	Name    string `json:"name,omitempty"`
	Stars   int    `json:"stars,omitempty"`
	Forks   int    `json:"forks,omitempty"`
	Watches int    `json:"watches,omitempty"`
	URL     string `json:"url,omitempty"`
}

type InTheWild struct {
	Source string `json:"source,omitempty"`
	URL    string `json:"url,omitempty"`
}

type Trickest struct {
	Description string       `json:"description,omitempty"`
	PoC         *TrickestPoc `json:"poc,omitempty"`
}

type TrickestPoc struct {
	Reference []string `json:"reference,omitempty"`
	GitHub    []string `json:"github,omitempty"`
}

type KEV struct {
	Title          string     `json:"title,omitempty"`
	Description    string     `json:"description,omitempty"`
	RequiredAction string     `json:"required_action,omitempty"`
	DueDate        *time.Time `json:"due_date,omitempty"`
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
