package types

import (
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/affected"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/exploit"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/metasploit"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/snort"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type Info struct {
	ID          string                  `json:"id,omitempty"`
	Title       string                  `json:"title,omitempty"`
	Description string                  `json:"description,omitempty"`
	Affected    []affected.Affected     `json:"affected,omitempty"`
	Severity    []severity.Severity     `json:"severity,omitempty"`
	CWE         []cwe.CWE               `json:"cwe,omitempty"`
	Exploit     []exploit.Exploit       `json:"exploit,omitempty"`
	Metasploit  []metasploit.Metasploit `json:"metasploit,omitempty"`
	EPSS        []epss.EPSS             `json:"epss,omitempty"`
	Snort       []snort.Snort           `json:"snort,omitempty"`
	References  []reference.Reference   `json:"references,omitempty"`
	Published   *time.Time              `json:"published,omitempty"`
	Modified    *time.Time              `json:"modified,omitempty"`
	DataSource  source.SourceID         `json:"data_source,omitempty"`
}

type CPEDictionary struct{}

type CWEDictionary struct{}

type CAPECDictionary struct{}

type AttackDictionary struct{}
