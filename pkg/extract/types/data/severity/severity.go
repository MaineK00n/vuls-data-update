package severity

import (
	"cmp"
	"encoding/json/v2"
	"fmt"

	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vendorTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/vendor"
)

type Severity struct {
	Type    SeverityType      `json:"type,omitempty"`
	Source  string            `json:"source,omitempty"`
	Vendor  *string           `json:"vendor,omitempty"`
	CVSSv2  *v2Types.CVSSv2   `json:"cvss_v2,omitempty"`
	CVSSv30 *v30Types.CVSSv30 `json:"cvss_v30,omitempty"`
	CVSSv31 *v31Types.CVSSv31 `json:"cvss_v31,omitempty"`
	CVSSv40 *v40Types.CVSSv40 `json:"cvss_v40,omitempty"`
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

func Compare(x, y Severity) int {
	return cmp.Or(
		cmp.Compare(x.Source, y.Source),
		cmp.Compare(x.Type, y.Type),
		func() int {
			switch x.Type {
			case SeverityTypeVendor:
				switch {
				case x.Vendor == nil && y.Vendor == nil:
					return 0
				case x.Vendor == nil && y.Vendor != nil:
					return -1
				case x.Vendor != nil && y.Vendor == nil:
					return +1
				default:
					return vendorTypes.Compare(x.Source, *x.Vendor, *y.Vendor)
				}
			case SeverityTypeCVSSv2:
				switch {
				case x.CVSSv2 == nil && y.CVSSv2 == nil:
					return 0
				case x.CVSSv2 == nil && y.CVSSv2 != nil:
					return -1
				case x.CVSSv2 != nil && y.CVSSv2 == nil:
					return +1
				default:
					return v2Types.Compare(*x.CVSSv2, *y.CVSSv2)
				}
			case SeverityTypeCVSSv30:
				switch {
				case x.CVSSv30 == nil && y.CVSSv30 == nil:
					return 0
				case x.CVSSv30 == nil && y.CVSSv30 != nil:
					return -1
				case x.CVSSv30 != nil && y.CVSSv30 == nil:
					return +1
				default:
					return v30Types.Compare(*x.CVSSv30, *y.CVSSv30)
				}
			case SeverityTypeCVSSv31:
				switch {
				case x.CVSSv31 == nil && y.CVSSv31 == nil:
					return 0
				case x.CVSSv31 == nil && y.CVSSv31 != nil:
					return -1
				case x.CVSSv31 != nil && y.CVSSv31 == nil:
					return +1
				default:
					return v31Types.Compare(*x.CVSSv31, *y.CVSSv31)
				}
			case SeverityTypeCVSSv40:
				switch {
				case x.CVSSv40 == nil && y.CVSSv40 == nil:
					return 0
				case x.CVSSv40 == nil && y.CVSSv40 != nil:
					return -1
				case x.CVSSv40 != nil && y.CVSSv40 == nil:
					return +1
				default:
					return v40Types.Compare(*x.CVSSv40, *y.CVSSv40)
				}
			default:
				return 0
			}
		}(),
	)
}
