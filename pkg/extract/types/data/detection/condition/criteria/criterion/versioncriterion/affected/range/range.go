package affectedrange

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	microsoftdefenderandroid "github.com/MaineK00n/go-microsoft-version/defender/android"
	microsoftdefenderios "github.com/MaineK00n/go-microsoft-version/defender/ios"
	microsoftdefenderiot "github.com/MaineK00n/go-microsoft-version/defender/iot"
	microsoftdefenderlinux "github.com/MaineK00n/go-microsoft-version/defender/linux"
	microsoftdefendermac "github.com/MaineK00n/go-microsoft-version/defender/mac"
	microsoftdefendersi "github.com/MaineK00n/go-microsoft-version/defender/securityintelligence"
	microsoftdefenderwindows "github.com/MaineK00n/go-microsoft-version/defender/windows"
	microsoftdotnetcore "github.com/MaineK00n/go-microsoft-version/dotnet/core"
	microsoftedge "github.com/MaineK00n/go-microsoft-version/edge"
	microsoftexchange "github.com/MaineK00n/go-microsoft-version/exchange"
	microsoftofficemac "github.com/MaineK00n/go-microsoft-version/office/mac"
	microsoftofficewindows "github.com/MaineK00n/go-microsoft-version/office/windows"
	microsoftsharepoint "github.com/MaineK00n/go-microsoft-version/sharepoint"
	microsoftsqlserver "github.com/MaineK00n/go-microsoft-version/sqlserver"
	microsoftteamsandroid "github.com/MaineK00n/go-microsoft-version/teams/android"
	microsoftteamsclient "github.com/MaineK00n/go-microsoft-version/teams/client"
	microsoftteamsdesktop "github.com/MaineK00n/go-microsoft-version/teams/desktop"
	microsoftteamsios "github.com/MaineK00n/go-microsoft-version/teams/ios"
	microsoftteamsmac "github.com/MaineK00n/go-microsoft-version/teams/mac"
	microsoftvisualstudio "github.com/MaineK00n/go-microsoft-version/visualstudio"
	microsoftvscode "github.com/MaineK00n/go-microsoft-version/vscode"
	microsoftwindows "github.com/MaineK00n/go-microsoft-version/windows"
	gem "github.com/aquasecurity/go-gem-version"
	npm "github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/hashicorp/go-version"
	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"
	mvn "github.com/masahiro331/go-mvn-version"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

// RangeType selects the version comparator used by CompareVersions (the
// Compare method is unrelated: it is the vocabulary ordering). It is a string
// so that unmarshaling never validates against the known set: data produced
// by a newer vuls-data-update (carrying range types this build does not know)
// still round-trips losslessly. CompareVersions answers such values with
// *UnsupportedRangeTypeError wrapped in *CompareError, which
// versioncriterion/affected.Accept degrades to a safe non-match, so an old
// binary skips the criterion instead of failing detection.
type RangeType string

const (
	RangeTypeVersion                               RangeType = "version"
	RangeTypeSEMVER                                RangeType = "semver"
	RangeTypeAPK                                   RangeType = "apk"
	RangeTypeRPM                                   RangeType = "rpm"
	RangeTypeRPMVersionOnly                        RangeType = "rpm-version-only"
	RangeTypeDPKG                                  RangeType = "dpkg"
	RangeTypePacman                                RangeType = "pacman"
	RangeTypeFreeBSDPkg                            RangeType = "freebsd-pkg"
	RangeTypeNPM                                   RangeType = "npm"
	RangeTypeRubyGems                              RangeType = "rubygems"
	RangeTypePyPI                                  RangeType = "pypi"
	RangeTypeMaven                                 RangeType = "maven"
	RangeTypeMicrosoftDefenderAndroid              RangeType = "microsoft-defender-android"
	RangeTypeMicrosoftDefenderIOS                  RangeType = "microsoft-defender-ios"
	RangeTypeMicrosoftDefenderIoT                  RangeType = "microsoft-defender-iot"
	RangeTypeMicrosoftDefenderLinux                RangeType = "microsoft-defender-linux"
	RangeTypeMicrosoftDefenderMac                  RangeType = "microsoft-defender-mac"
	RangeTypeMicrosoftDefenderSecurityIntelligence RangeType = "microsoft-defender-security-intelligence"
	RangeTypeMicrosoftDefenderWindows              RangeType = "microsoft-defender-windows"
	RangeTypeMicrosoftDotNetCore                   RangeType = "microsoft-dotnet-core"
	RangeTypeMicrosoftEdge                         RangeType = "microsoft-edge"
	RangeTypeMicrosoftExchange                     RangeType = "microsoft-exchange"
	RangeTypeMicrosoftOfficeMac                    RangeType = "microsoft-office-mac"
	RangeTypeMicrosoftOfficeWindows                RangeType = "microsoft-office-windows"
	RangeTypeMicrosoftSharePoint                   RangeType = "microsoft-sharepoint"
	RangeTypeMicrosoftSQLServer                    RangeType = "microsoft-sqlserver"
	RangeTypeMicrosoftTeamsAndroid                 RangeType = "microsoft-teams-android"
	RangeTypeMicrosoftTeamsClient                  RangeType = "microsoft-teams-client"
	RangeTypeMicrosoftTeamsDesktop                 RangeType = "microsoft-teams-desktop"
	RangeTypeMicrosoftTeamsIOS                     RangeType = "microsoft-teams-ios"
	RangeTypeMicrosoftTeamsMac                     RangeType = "microsoft-teams-mac"
	RangeTypeMicrosoftVisualStudio                 RangeType = "microsoft-visualstudio"
	RangeTypeMicrosoftVSCode                       RangeType = "microsoft-vscode"
	RangeTypeMicrosoftWindows                      RangeType = "microsoft-windows"

	RangeTypeUnknown RangeType = "unknown"
)

// RangeTypes returns every RangeType this build knows, in declaration order.
// Consumers (vuls2, vuls0) diff this list against a newer vuls-data-update in
// CI to detect enum additions that require a dependency bump. The known set
// must be append-only: removing or renaming a value would leave already
// extracted data undetectable by builds that follow the removal.
func RangeTypes() []RangeType {
	return []RangeType{
		RangeTypeVersion,
		RangeTypeSEMVER,
		RangeTypeAPK,
		RangeTypeRPM,
		RangeTypeRPMVersionOnly,
		RangeTypeDPKG,
		RangeTypePacman,
		RangeTypeFreeBSDPkg,
		RangeTypeNPM,
		RangeTypeRubyGems,
		RangeTypePyPI,
		RangeTypeMaven,
		RangeTypeMicrosoftDefenderAndroid,
		RangeTypeMicrosoftDefenderIOS,
		RangeTypeMicrosoftDefenderIoT,
		RangeTypeMicrosoftDefenderLinux,
		RangeTypeMicrosoftDefenderMac,
		RangeTypeMicrosoftDefenderSecurityIntelligence,
		RangeTypeMicrosoftDefenderWindows,
		RangeTypeMicrosoftDotNetCore,
		RangeTypeMicrosoftEdge,
		RangeTypeMicrosoftExchange,
		RangeTypeMicrosoftOfficeMac,
		RangeTypeMicrosoftOfficeWindows,
		RangeTypeMicrosoftSharePoint,
		RangeTypeMicrosoftSQLServer,
		RangeTypeMicrosoftTeamsAndroid,
		RangeTypeMicrosoftTeamsClient,
		RangeTypeMicrosoftTeamsDesktop,
		RangeTypeMicrosoftTeamsIOS,
		RangeTypeMicrosoftTeamsMac,
		RangeTypeMicrosoftVisualStudio,
		RangeTypeMicrosoftVSCode,
		RangeTypeMicrosoftWindows,
		RangeTypeUnknown,
	}
}

// Compare orders t against u by vocabulary rank — the declaration order of
// RangeTypes() — preserving the canonical output order from before the
// string conversion. Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (t RangeType) Compare(u RangeType) int {
	return vocabulary.Compare(t, u)
}

var vocabulary = enum.NewVocabulary(RangeTypes())

// comparatorless lists vocabulary values that have never had a comparator —
// pre-existing debt, not a template: CompareVersions answers them with
// *UnsupportedRangeTypeError and evaluation degrades silently. Do not add
// new types here; a new RangeType must ship with its comparator.
var comparatorless = map[RangeType]struct{}{
	RangeTypePacman:     {},
	RangeTypeFreeBSDPkg: {},
}

// Evaluable reports whether this build can actually evaluate t: it is in the
// vocabulary AND has a comparator. Known but comparator-less debt (pacman,
// freebsd-pkg) is not evaluable.
func (t RangeType) Evaluable() bool {
	if _, ok := comparatorless[t]; ok {
		return false
	}
	return vocabulary.Contains(t)
}

// Known reports whether t is in this build's vocabulary — i.e. whether this
// build can be expected to evaluate it (modulo comparator-less debt, see
// UnsupportedRangeTypeError). Data from a newer vuls-data-update may carry
// values for which Known is false.
func (t RangeType) Known() bool {
	return vocabulary.Contains(t)
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
	return fmt.Sprintf("cannot compare versions. %s", e.Reason)
}

// UnsupportedRangeTypeError is wrapped in a *CompareError when
// CompareVersions is called with a RangeType this build has no comparator
// for. That is usually a value outside the vocabulary — produced by a newer
// vuls-data-update and read by an older binary, or the zero value (unset — a
// producer-side bug; check the RangeType field to tell the two apart) — but
// also covers the vocabulary values pacman and freebsd-pkg, whose
// comparators were never implemented (pre-existing debt). Only the declared
// "unknown" vocabulary value classifies as ErrRangeTypeUnknown instead.
// Callers that need to tell these anomalies apart from ordinary parse
// failures can errors.As for this type through the CompareError chain.
type UnsupportedRangeTypeError struct {
	RangeType RangeType
}

func (e *UnsupportedRangeTypeError) Error() string {
	return fmt.Sprintf("unsupported range type %q", string(e.RangeType))
}

var ErrRangeTypeUnknown = errors.New("unknown range type")

// CompareVersions returns an integer comparing v1 and v2 under the
// comparator selected by t: negative for v1 < v2, zero for equal, positive
// for v1 > v2.
func (t RangeType) CompareVersions(family ecosystemTypes.Ecosystem, v1, v2 string) (int, error) {
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
		case ecosystemTypes.EcosystemTypeCentOS:
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
	case RangeTypeMicrosoftDefenderAndroid:
		va, err := microsoftdefenderandroid.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdefenderandroid.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftDefenderIOS:
		va, err := microsoftdefenderios.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdefenderios.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftDefenderIoT:
		va, err := microsoftdefenderiot.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdefenderiot.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftDefenderLinux:
		va, err := microsoftdefenderlinux.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdefenderlinux.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftDefenderMac:
		va, err := microsoftdefendermac.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdefendermac.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftDefenderSecurityIntelligence:
		va, err := microsoftdefendersi.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdefendersi.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftDefenderWindows:
		va, err := microsoftdefenderwindows.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdefenderwindows.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftDotNetCore:
		va, err := microsoftdotnetcore.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftdotnetcore.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftEdge:
		va, err := microsoftedge.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftedge.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftExchange:
		va, err := microsoftexchange.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftexchange.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftOfficeMac:
		va, err := microsoftofficemac.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftofficemac.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftOfficeWindows:
		va, err := microsoftofficewindows.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftofficewindows.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftSharePoint:
		va, err := microsoftsharepoint.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftsharepoint.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftSQLServer:
		va, err := microsoftsqlserver.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftsqlserver.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftTeamsAndroid:
		va, err := microsoftteamsandroid.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftteamsandroid.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftTeamsClient:
		va, err := microsoftteamsclient.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftteamsclient.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftTeamsDesktop:
		va, err := microsoftteamsdesktop.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftteamsdesktop.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftTeamsIOS:
		va, err := microsoftteamsios.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftteamsios.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftTeamsMac:
		va, err := microsoftteamsmac.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftteamsmac.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftVisualStudio:
		va, err := microsoftvisualstudio.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftvisualstudio.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftVSCode:
		va, err := microsoftvscode.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftvscode.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeMicrosoftWindows:
		va, err := microsoftwindows.NewVersion(v1)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v1, Err: err}}
		}
		vb, err := microsoftwindows.NewVersion(v2)
		if err != nil {
			return 0, &CompareError{Err: &NewVersionError{RangeType: t, Version: v2, Err: err}}
		}
		return va.Compare(vb), nil
	case RangeTypeUnknown:
		// The declared "unknown" vocabulary value is normal data (e.g. NVD
		// emits it for ranges it cannot express); it quietly cannot evaluate.
		return 0, &CompareError{Err: ErrRangeTypeUnknown}
	default:
		// Everything outside the vocabulary — the zero value (unset, a
		// producer-side bug) or a value this build does not know (data from
		// a newer vuls-data-update) — is an anomaly worth surfacing, so it
		// classifies as *UnsupportedRangeTypeError (the two are told apart
		// via its RangeType field). Wrapping in *CompareError still lets
		// versioncriterion/affected.Accept degrade to a safe non-match
		// instead of aborting detection on an old binary.
		return 0, &CompareError{Err: &UnsupportedRangeTypeError{RangeType: t}}
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
