package build

import "time"

type Vulnerability struct {
	ID          string        `json:"id,omitempty"`
	Advisory    *Advisories   `json:"advisory,omitempty"`
	Title       *Titles       `json:"title,omitempty"`
	Description *Descriptions `json:"description,omitempty"`
	CVSS        *CVSSes       `json:"cvss,omitempty"`
	EPSS        *EPSS         `json:"epss,omitempty"`
	CWE         *CWEs         `json:"cwe,omitempty"`
	Metasploit  []Metasploit  `json:"metasploit,omitempty"`
	Exploit     *Exploit      `json:"exploit,omitempty"`
	KEV         *KEV          `json:"kev,omitempty"`
	Mitigation  *Mitigation   `json:"mitigation,omitempty"`
	Published   *Publisheds   `json:"published,omitempty"`
	Modified    *Modifieds    `json:"modified,omitempty"`
	References  *References   `json:"references,omitempty"`
}

type Advisories struct {
	MITRE *Advisory  `json:"mitre,omitempty"`
	NVD   *Advisory  `json:"nvd,omitempty"`
	JVN   []Advisory `json:"jvn,omitempty"`
	Alma  []Advisory `json:"alma,omitempty"`
}
type Advisory struct {
	ID  string `json:"id,omitempty"`
	URL string `json:"url,omitempty"`
}

type Titles struct {
	MITRE string            `json:"mitre,omitempty"`
	NVD   string            `json:"nvd,omitempty"`
	JVN   map[string]string `json:"jvn,omitempty"`
	Alma  map[string]string `json:"alma,omitempty"`
}

type Descriptions struct {
	MITRE string            `json:"mitre,omitempty"`
	NVD   string            `json:"nvd,omitempty"`
	JVN   map[string]string `json:"jvn,omitempty"`
	Alma  map[string]string `json:"alma,omitempty"`
}

type CVSSes struct {
	NVD  []CVSS            `json:"nvd,omitempty"`
	JVN  map[string][]CVSS `json:"jvn,omitempty"`
	Alma map[string][]CVSS `json:"alma,omitempty"`
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

type CWEs struct {
	NVD []string            `json:"nvd,omitempty"`
	JVN map[string][]string `json:"jvn,omitempty"`
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
	Stars   int    `json:"stars"`
	Forks   int    `json:"forks"`
	Watches int    `json:"watches"`
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

type Mitigation struct {
	NVD []string `json:"nvd,omitempty"`
}

type Publisheds struct {
	MITRE *time.Time            `json:"mitre,omitempty"`
	NVD   *time.Time            `json:"nvd,omitempty"`
	JVN   map[string]*time.Time `json:"jvn,omitempty"`
	Alma  map[string]*time.Time `json:"alma,omitempty"`
}

type Modifieds struct {
	MITRE *time.Time            `json:"mitre,omitempty"`
	NVD   *time.Time            `json:"nvd,omitempty"`
	JVN   map[string]*time.Time `json:"jvn,omitempty"`
	Alma  map[string]*time.Time `json:"alma,omitempty"`
}

type References struct {
	MITRE []Reference            `json:"mitre,omitempty"`
	NVD   []Reference            `json:"nvd,omitempty"`
	JVN   map[string][]Reference `json:"jvn,omitempty"`
	Alma  map[string][]Reference `json:"alma,omitempty"`
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
	Version               string  `json:"version,omitempty"`
	CPE                   string  `json:"cpe,omitempty"`
	VersionEndExcluding   *string `json:"version_end_excluding,omitempty"`
	VersionEndIncluding   *string `json:"version_end_including,omitempty"`
	VersionStartExcluding *string `json:"version_start_excluding,omitempty"`
	VersionStartIncluding *string `json:"version_start_including,omitempty"`
}

type DetectPackage struct {
	ID       string    `json:"id,omitempty"`
	Packages []Package `json:"packages,omitempty"`
}

type Package struct {
	Name            string   `json:"name,omitempty"`
	Status          string   `json:"status,omitempty"`
	FixedVersion    string   `json:"fixed_version,omitempty"`
	ModularityLabel string   `json:"modularity_label,omitempty"`
	Arch            []string `json:"arch,omitempty"`
}
