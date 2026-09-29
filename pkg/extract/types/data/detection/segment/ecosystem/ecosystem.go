package ecosystem

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

// solarisReleasePattern is the shape of a Solaris release, capturing the part
// that keys the ecosystem. Solaris 10 is one release, so anything after the
// major (an update number a scanner may record) is dropped. Solaris 11 is a
// family of minor releases (11.3, 11.4, ...) that are supported and updated
// independently, so the minor keys the ecosystem and anything after it is
// dropped. Zero padding is rejected only where it would key an ecosystem of
// its own: "11.04" is not "11.4", while "10.04" is Solaris 10 like any other
// update level.
var solarisReleasePattern = regexp.MustCompile(`^(10|11\.(?:0|[1-9][0-9]*))(?:\.[0-9]+)*$`)

type Ecosystem string

const (
	EcosystemTypeAlma                = "alma"
	EcosystemTypeAlpine              = "alpine"
	EcosystemTypeAmazon              = "amazon"
	EcosystemTypeArch                = "arch"
	EcosystemTypeCentOS              = "centos"
	EcosystemTypeDebian              = "debian"
	EcosystemTypeEPEL                = "epel"
	EcosystemTypeEPELNext            = "epel-next"
	EcosystemTypeFedora              = "fedora"
	EcosystemTypeFreeBSD             = "freebsd"
	EcosystemTypeGentoo              = "gentoo"
	EcosystemTypeMicrosoft           = "microsoft"
	EcosystemTypeNetBSD              = "netbsd"
	EcosystemTypeOracle              = "oracle"
	EcosystemTypeRedHat              = "redhat"
	EcosystemTypeRocky               = "rocky"
	EcosystemTypeSolaris             = "solaris"
	EcosystemTypeOpenSUSE            = "opensuse"
	EcosystemTypeOpenSUSELeap        = "opensuse.leap"
	EcosystemTypeOpenSUSELeapMicro   = "opensuse.leap.micro"
	EcosystemTypeOpenSUSETumbleweed  = "opensuse.tumbleweed"
	EcosystemTypeSUSELinuxEnterprise = "suse.linux.enterprise"
	EcosystemTypeSUSELinuxMicro      = "suse.linux.micro"
	EcosystemTypeUbuntu              = "ubuntu"

	EcosystemTypeCPE = "cpe"

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

func GetEcosystem(family, release string) (Ecosystem, error) {
	switch family {
	case EcosystemTypeAlma:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeAlpine:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])), nil
	case EcosystemTypeAmazon:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeArch:
		return Ecosystem(family), nil
	case EcosystemTypeCentOS:
		return Ecosystem(fmt.Sprintf("%s:%s", EcosystemTypeRedHat, strings.Split(release, ".")[0])), nil
	case EcosystemTypeDebian:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeEPEL:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeEPELNext:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeFedora:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeFreeBSD:
		return Ecosystem(family), nil
	case EcosystemTypeGentoo:
		return Ecosystem(family), nil
	case EcosystemTypeNetBSD:
		return Ecosystem(family), nil
	case EcosystemTypeOracle:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeRedHat:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeRocky:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeSolaris:
		m := solarisReleasePattern.FindStringSubmatch(release)
		if m == nil {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "10(.<n>...) or 11.<minor>(.<n>...), <minor> without zero padding", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s", family, m[1])), nil
	case EcosystemTypeOpenSUSE:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeOpenSUSELeap:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeOpenSUSELeapMicro:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeOpenSUSETumbleweed:
		return EcosystemTypeOpenSUSETumbleweed, nil
	case EcosystemTypeSUSELinuxEnterprise:
		return Ecosystem(fmt.Sprintf("%s:%s", EcosystemTypeSUSELinuxEnterprise, strings.Split(release, ".")[0])), nil
	case EcosystemTypeSUSELinuxMicro:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeUbuntu:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])), nil
	case EcosystemTypeMicrosoft:
		return Ecosystem(family), nil
	case EcosystemTypeCPE:
		return Ecosystem(family), nil
	case EcosystemTypeFortinet:
		return Ecosystem(family), nil
	case EcosystemTypeCargo:
		return Ecosystem(family), nil
	case EcosystemTypeComposer:
		return Ecosystem(family), nil
	case EcosystemTypeConan:
		return Ecosystem(family), nil
	case EcosystemTypeErlang:
		return Ecosystem(family), nil
	case EcosystemTypeGolang:
		return Ecosystem(family), nil
	case EcosystemTypeHaskell:
		return Ecosystem(family), nil
	case EcosystemTypeMaven:
		return Ecosystem(family), nil
	case EcosystemTypeNpm:
		return Ecosystem(family), nil
	case EcosystemTypeNuget:
		return Ecosystem(family), nil
	case EcosystemTypePerl:
		return Ecosystem(family), nil
	case EcosystemTypePip:
		return Ecosystem(family), nil
	case EcosystemTypePub:
		return Ecosystem(family), nil
	case EcosystemTypeR:
		return Ecosystem(family), nil
	case EcosystemTypeRubygems:
		return Ecosystem(family), nil
	case EcosystemTypeSwift:
		return Ecosystem(family), nil
	default:
		return "", errors.Errorf("unexpected family. expected: %q, actual: %q", []Ecosystem{EcosystemTypeAlma, EcosystemTypeAlpine, EcosystemTypeAmazon, EcosystemTypeArch, EcosystemTypeCentOS, EcosystemTypeDebian, EcosystemTypeEPEL, EcosystemTypeFedora, EcosystemTypeFreeBSD, EcosystemTypeGentoo, EcosystemTypeMicrosoft, EcosystemTypeNetBSD, EcosystemTypeOracle, EcosystemTypeRedHat, EcosystemTypeRocky, EcosystemTypeSolaris, EcosystemTypeOpenSUSE, EcosystemTypeOpenSUSELeap, EcosystemTypeOpenSUSELeapMicro, EcosystemTypeOpenSUSETumbleweed, EcosystemTypeSUSELinuxEnterprise, EcosystemTypeSUSELinuxMicro, EcosystemTypeUbuntu, EcosystemTypeCPE, EcosystemTypeFortinet, EcosystemTypeCargo, EcosystemTypeComposer, EcosystemTypeConan, EcosystemTypeErlang, EcosystemTypeGolang, EcosystemTypeHaskell, EcosystemTypeMaven, EcosystemTypeNpm, EcosystemTypeNuget, EcosystemTypePerl, EcosystemTypePip, EcosystemTypePub, EcosystemTypeR, EcosystemTypeRubygems, EcosystemTypeSwift}, family)
	}
}
