package detection

import (
	"encoding/json"
	"fmt"
)

type Detection struct {
	Ecosystem  string    `json:"ecosystem,omitempty"`
	Vulnerable bool      `json:"vulnerable,omitempty"`
	Package    Package   `json:"package,omitempty"`
	Affected   *Affected `json:"affected,omitempty"`
	Criteria   *Criteria `json:"criteria,omitempty"`
}

const (
	EcosystemTypeAlma        = "alma"
	EcosystemTypeAlpine      = "alpine"
	EcosystemTypeAmazon      = "amazon"
	EcosystemTypeArch        = "arch"
	EcosystemTypeDebian      = "debian"
	EcosystemTypeEPEL        = "epel"
	EcosystemTypeFedora      = "fedora"
	EcosystemTypeFreeBSD     = "freebsd"
	EcosystemTypeGentoo      = "gentoo"
	EcosystemTypeNetBSD      = "netbsd"
	EcosystemTypeOracle      = "oracle"
	EcosystemTypeRedHat      = "redhat"
	EcosystemTypeRocky       = "rocky"
	EcosystemTypeOpenSUSE    = "opensuse"
	EcosystemTypeSUSEServer  = "sles"
	EcosystemTypeSUSEDesktop = "sled"
	EcosystemTypeUbuntu      = "ubuntu"
	EcosystemTypeWindows     = "windows"

	EcosystemTypeFortinet = "fortinet"

	EcosystemTypeCargo    = "cargo"
	EcosystemTypeComposer = "composer"
	EcosystemTypeConan    = "conan"
	EcosystemTypeErlang   = "erlang"
	EcosystemTypeGolang   = "golang"
	EcosystemTypeHaskell  = "haskell"
	EcosystemTypeMaven    = "maven"
	EcosystemTypeNpm      = "npm"
	EcosystemTypeNuget    = "nuget"
	EcosystemTypePerl     = "perl"
	EcosystemTypePip      = "pip"
	EcosystemTypePub      = "pub"
	EcosystemTypeR        = "r"
	EcosystemTypeRubygems = "rubygems"
	EcosystemTypeSwift    = "swift"
)

type Package struct {
	Name          string   `json:"name,omitempty"`
	CPE           string   `json:"cpe,omitempty"`
	Repositories  []string `json:"repositories,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Functions     []string `json:"functions,omitempty"`
}

type Affected struct {
	Type  RangeType `json:"type,omitempty"`
	Range []Range   `json:"range,omitempty"`
	Fixed []string  `json:"fixed,omitempty"`
}

type RangeType int

const (
	_ RangeType = iota
	RangeTypeVersion
	RangeTypeSEMVER
	RangeTypeAPK
	RangeTypeRPM
	RangeTypeDPKG
	RangeTypePacman
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

func (a Affected) LessThan(v string) (bool, error) {
	// TODO:
	return false, nil
}

type Range struct {
	Equal        string `json:"eq,omitempty"`
	LessThan     string `json:"lt,omitempty"`
	LessEqual    string `json:"le,omitempty"`
	GreaterThan  string `json:"gt,omitempty"`
	GreaterEqual string `json:"ge,omitempty"`
}

type Criteria struct {
	Operator   CriteriaOperatorType `json:"operator,omitempty"`
	Criterias  []Criteria           `json:"criterias,omitempty"`
	Criterions []string             `json:"criterions,omitempty"`
}

type CriteriaOperatorType int

const (
	_ CriteriaOperatorType = iota
	CriteriaOperatorTypeOR
	CriteriaOperatorTypeAND
)

func (t CriteriaOperatorType) String() string {
	switch t {
	case CriteriaOperatorTypeOR:
		return "OR"
	case CriteriaOperatorTypeAND:
		return "AND"
	default:
		return ""
	}
}

func (t CriteriaOperatorType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *CriteriaOperatorType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var ct CriteriaOperatorType
	switch s {
	case "OR":
		ct = CriteriaOperatorTypeOR
	case "AND":
		ct = CriteriaOperatorTypeAND
	default:
		return fmt.Errorf("invalid CriteriaOperatorType %s", s)
	}
	*t = ct
	return nil
}
