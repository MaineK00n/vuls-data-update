package affectedrange

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"

	gem "github.com/aquasecurity/go-gem-version"
	npm "github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/hashicorp/go-version"
	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"
	mvn "github.com/masahiro331/go-mvn-version"
	"github.com/pkg/errors"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type RangeType int

const (
	_ RangeType = iota
	RangeTypeVersion
	RangeTypeSEMVER
	RangeTypeAPK
	RangeTypeRPM
	RangeTypeRPMVersionOnly
	RangeTypeDPKG
	RangeTypePacman
	RangeTypeFreeBSDPkg
	RangeTypeNPM
	RangeTypeRubyGems
	RangeTypePyPI
	RangeTypeMaven

	RangeTypeUnknown
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
	case RangeTypeRPMVersionOnly:
		return "rpm-version-only"
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
	case RangeTypeUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

func (t RangeType) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(t.String()))
}

func (t *RangeType) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '"' {
		return fmt.Errorf("unexpected type. expected: %s, got %s", "string", token.Kind())
	}

	switch token.String() {
	case "version":
		*t = RangeTypeVersion
	case "semver":
		*t = RangeTypeSEMVER
	case "apk":
		*t = RangeTypeAPK
	case "rpm":
		*t = RangeTypeRPM
	case "rpm-version-only":
		*t = RangeTypeRPMVersionOnly
	case "dpkg":
		*t = RangeTypeDPKG
	case "pacman":
		*t = RangeTypePacman
	case "freebsd-pkg":
		*t = RangeTypeFreeBSDPkg
	case "npm":
		*t = RangeTypeNPM
	case "rubygems":
		*t = RangeTypeRubyGems
	case "pypi":
		*t = RangeTypePyPI
	case "maven":
		*t = RangeTypeMaven
	case "unknown":
		*t = RangeTypeUnknown
	default:
		return fmt.Errorf("invalid CriterionType %s", token.String())
	}
	return nil
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
	case "rpm-version-only":
		rt = RangeTypeRPMVersionOnly
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
	case "unknown":
		rt = RangeTypeUnknown
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
	return cmp.Or(
		cmp.Compare(x.Equal, y.Equal),
		cmp.Compare(x.LessThan, y.LessThan),
		cmp.Compare(x.LessEqual, y.LessEqual),
		cmp.Compare(x.GreaterThan, y.GreaterThan),
		cmp.Compare(x.GreaterEqual, y.GreaterEqual),
	)
}

type CompareError struct {
	Err error
}

func (e *CompareError) Error() string {
	return fmt.Sprintf("compare error. err: %v", e.Err)
}

func (e *CompareError) Unwrap() error { return e.Err }

type NewVersionError struct {
	RangeType RangeType
	Version   string
	Err       error
}

func (e *NewVersionError) Error() string {
	return fmt.Sprintf("new version type %q, string %q: %v", e.RangeType, e.Version, e.Err)
}

func (e *NewVersionError) Unwrap() error { return e.Err }

type CannotCompareError struct {
	Reason string
}

func (e *CannotCompareError) Error() string {
	return fmt.Sprintf("cannot version comare. %s", e.Reason)
}

var ErrRangeTypeUnknown = errors.New("unknown range type")

func (t RangeType) Compare(family ecosystemTypes.Ecosystem, v1, v2 string) (int, error) {
	switch t {
	case RangeTypeVersion:
		va, err := version.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := version.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeSEMVER:
		va, err := version.NewSemver(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := version.NewSemver(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeAPK:
		va, err := apk.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := apk.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeRPM:
		switch family {
		case ecosystemTypes.EcosytemCentOS:
			if strings.Contains(v1, ".centos") != strings.Contains(v2, ".centos") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non centos package and centos package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			if strings.Contains(v1, ".module_el") != strings.Contains(v2, ".module_el") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non modular package and modular package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			if extractRedHatMajorVersion(v1) != extractRedHatMajorVersion(v2) {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("different major versions cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			return rpm.NewVersion(v1).Compare(rpm.NewVersion(v2)), nil
		case ecosystemTypes.EcosystemTypeAlma:
			if strings.Contains(v1, ".module_el") != strings.Contains(v2, ".module_el") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non modular package and modular package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			return rpm.NewVersion(v1).Compare(rpm.NewVersion(v2)), nil
		case ecosystemTypes.EcosystemTypeRocky:
			if strings.Contains(v1, ".cloud") != strings.Contains(v2, ".cloud") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("Rocky Linux package and Rocky Linux SIG Cloud package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			if strings.Contains(v1, ".module+el") != strings.Contains(v2, ".module+el") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non modular package and modular package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			return rpm.NewVersion(v1).Compare(rpm.NewVersion(v2)), nil
		case ecosystemTypes.EcosystemTypeOracle:
			if extractOracleKsplice(v1) != extractOracleKsplice(v2) {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("v1: %q and v2: %q do not match ksplice number", v1, v2)}}
			}
			if strings.HasSuffix(v1, "_fips") != strings.HasSuffix(v2, "_fips") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non fips package and fips package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			if strings.Contains(v1, ".module+el") != strings.Contains(v2, ".module+el") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non modular package and modular package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			return rpm.NewVersion(v1).Compare(rpm.NewVersion(v2)), nil
		case ecosystemTypes.EcosystemTypeFedora:
			if strings.Contains(v1, ".module_f") != strings.Contains(v2, ".module_f") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non modular package and modular package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			return rpm.NewVersion(v1).Compare(rpm.NewVersion(v2)), nil
		default:
			if strings.Contains(v1, ".module+el") != strings.Contains(v2, ".module+el") {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("non modular package and modular package cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			if extractRedHatMajorVersion(v1) != extractRedHatMajorVersion(v2) {
				return 0, &CompareError{Err: &CannotCompareError{Reason: fmt.Sprintf("different major versions cannot be compared. v1: %q, v2: %q", v1, v2)}}
			}
			return rpm.NewVersion(v1).Compare(rpm.NewVersion(v2)), nil
		}
	case RangeTypeRPMVersionOnly:
		va := rpm.NewVersion(v1)
		vb := rpm.NewVersion(v2)
		return rpm.NewVersion(va.Version()).Compare(rpm.NewVersion(vb.Version())), nil
	case RangeTypeDPKG:
		va, err := deb.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := deb.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeNPM:
		va, err := npm.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := npm.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeRubyGems:
		va, err := gem.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := gem.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypePyPI:
		va, err := pep440.Parse(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := pep440.Parse(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMaven:
		va, err := mvn.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := mvn.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeUnknown:
		return 0, &CompareError{Err: ErrRangeTypeUnknown}
	default:
		return 0, errors.Errorf("unsupported range type: %s", t)
	}
}

func extractRedHatMajorVersion(v string) string {
	_, rhs, ok := strings.Cut(v, ".el")
	if ok {
		return strings.Split(strings.Split(rhs, ".")[0], "_")[0]
	}

	_, rhs, ok = strings.Cut(v, ".module+el")
	if ok {
		return strings.Split(strings.Split(rhs, ".")[0], "_")[0]
	}

	return ""
}

func extractOracleKsplice(v string) string {
	_, rhs, ok := strings.Cut(v, ".ksplice")
	if ok {
		return strings.Split(rhs, ".")[0]
	}
	return ""
}
