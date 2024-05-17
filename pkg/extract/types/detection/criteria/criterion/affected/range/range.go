package affectedrange

import (
	"cmp"
	"encoding/json"
	"fmt"
)

type RangeType int

const (
	_ RangeType = iota
	RangeTypeVersion
	RangeTypeSEMVER
	RangeTypeAPK
	RangeTypeRPM
	RangeTypeDPKG
	RangeTypePacman
	RangeTypeFreeBSDPkg
	RangeTypeNPM
	RangeTypeRubyGems
	RangeTypePyPI
	RangeTypeMaven
)

func (t RangeType) String() string {
	switch t {
	case RangeTypeVersion:
		return "version"
	case RangeTypeSEMVER:
		return "semver"
	case RangeTypeAPK:
		return "apk"
	case RangeTypeRPM:
		return "rpm"
	case RangeTypeDPKG:
		return "dpkg"
	case RangeTypePacman:
		return "pacman"
	case RangeTypeFreeBSDPkg:
		return "freebsd-pkg"
	case RangeTypeNPM:
		return "npm"
	case RangeTypeRubyGems:
		return "rubygems"
	case RangeTypePyPI:
		return "pypi"
	case RangeTypeMaven:
		return "maven"
	default:
		return "version"
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
	case "version":
		rt = RangeTypeVersion
	case "semver":
		rt = RangeTypeSEMVER
	case "apk":
		rt = RangeTypeAPK
	case "rpm":
		rt = RangeTypeRPM
	case "dpkg":
		rt = RangeTypeDPKG
	case "pacman":
		rt = RangeTypePacman
	case "freebsd-pkg":
		rt = RangeTypeFreeBSDPkg
	case "npm":
		rt = RangeTypeNPM
	case "rubygems":
		rt = RangeTypeRubyGems
	case "pypi":
		rt = RangeTypePyPI
	case "maven":
		rt = RangeTypeMaven
	default:
		return fmt.Errorf("invalid RangeType %s", s)
	}
	*t = rt
	return nil
}

type Range struct {
	Equal        string `json:"eq,omitempty"`
	LessThan     string `json:"lt,omitempty"`
	LessEqual    string `json:"le,omitempty"`
	GreaterThan  string `json:"gt,omitempty"`
	GreaterEqual string `json:"ge,omitempty"`
}

func Compare(x, y Range) int {
	if c := cmp.Compare(x.Equal, y.Equal); c != 0 {
		return c
	}
	if c := cmp.Compare(x.LessThan, y.LessThan); c != 0 {
		return c
	}
	if c := cmp.Compare(x.LessEqual, y.LessEqual); c != 0 {
		return c
	}
	if c := cmp.Compare(x.GreaterThan, y.GreaterThan); c != 0 {
		return c
	}
	return cmp.Compare(x.GreaterEqual, y.GreaterEqual)
}
