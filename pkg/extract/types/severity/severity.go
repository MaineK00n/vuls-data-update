package severity

import (
	"encoding/json"
	"fmt"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v2"
	v30 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v30"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v31"
	v40 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v40"
)

type Severity struct {
	Type    SeverityType `json:"type,omitempty"`
	Source  string       `json:"source,omitempty"`
	Vendor  *string      `json:"vendor,omitempty"`
	CVSSv2  *v2.CVSSv2   `json:"cvss_v2,omitempty"`
	CVSSv30 *v30.CVSSv30 `json:"cvss_v30,omitempty"`
	CVSSv31 *v31.CVSSv31 `json:"cvss_v31,omitempty"`
	CVSSv40 *v40.CVSSv40 `json:"cvss_v40,omitempty"`
}

type SeverityType int

const (
	_ SeverityType = iota
	SeverityTypeVendor
	SeverityTypeCVSSv2
	SeverityTypeCVSSv30
	SeverityTypeCVSSv31
	SeverityTypeCVSSv40
)

func (t SeverityType) String() string {
	switch t {
	case SeverityTypeVendor:
		return "vendor"
	case SeverityTypeCVSSv2:
		return "cvss_v2"
	case SeverityTypeCVSSv30:
		return "cvss_v30"
	case SeverityTypeCVSSv31:
		return "cvss_v31"
	case SeverityTypeCVSSv40:
		return "cvss_v40"
	default:
		return ""
	}
}

func (t SeverityType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *SeverityType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var st SeverityType
	switch s {
	case "vendor":
		st = SeverityTypeVendor
	case "cvss_v2":
		st = SeverityTypeCVSSv2
	case "cvss_v30":
		st = SeverityTypeCVSSv30
	case "cvss_v31":
		st = SeverityTypeCVSSv31
	case "cvss_v40":
		st = SeverityTypeCVSSv40
	default:
		return fmt.Errorf("invalid SeverityType %s", s)
	}
	*t = st
	return nil
}
