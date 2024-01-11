package affected

import (
	"encoding/json"
	"fmt"
)

type Affected struct {
	Vulnerable     bool       `json:"vulnerable,omitempty"`
	Package        Package    `json:"package,omitempty"`
	Ranges         []Range    `json:"ranges,omitempty"`
	Versions       []string   `json:"versions,omitempty"`
	Configurations []Affected `json:"configurations,omitempty"`
}

type Package struct {
	Ecosystem    string   `json:"ecosystem,omitempty"`
	Name         string   `json:"name,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
	Arches       []string `json:"arches,omitempty"`
}

const (
	EcosystemTypeAlma = "AlmaLinux:%s"
)

type Range struct {
	Type   RangeType `json:"type,omitempty"`
	Events []Event   `json:"events,omitempty"`
}

type RangeType int

const (
	_ RangeType = iota
	RangeTypeSEMVER
	RangeTypeEcosystem
	RangeTypeGit
)

func (t RangeType) String() string {
	switch t {
	case RangeTypeSEMVER:
		return "SEMVER"
	case RangeTypeEcosystem:
		return "ECOSYSTEM"
	case RangeTypeGit:
		return "GIT"
	default:
		return ""
	}
}

func (t RangeType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *RangeType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var rt RangeType
	switch s {
	case "SEMVER":
		rt = RangeTypeSEMVER
	case "ECOSYSTEM":
		rt = RangeTypeEcosystem
	case "GIT":
		rt = RangeTypeGit
	default:
		return fmt.Errorf("invalid RangeType %s", s)
	}
	*t = rt
	return nil
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
