package oval

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

type Variant string

const (
	VariantNone     Variant = ""
	VariantAffected Variant = "affected"
	VariantPatch    Variant = "patch"
)

type FileKey struct {
	OS      string
	Version string
}

type FileName struct {
	Raw     string
	OS      string
	Version string
	Variant Variant
}

func (f FileName) Key() FileKey {
	return FileKey{OS: f.OS, Version: f.Version}
}

func (f FileName) OvalType() string {
	if f.Variant == VariantPatch {
		return "patch"
	}
	return "vulnerability"
}

// ShouldInclude returns true if this file should be included in the fetch.
func (f FileName) ShouldInclude() bool {
	switch f.OS {
	case "opensuse", "opensuse.leap", "opensuse.leap.micro":
		return true
	case "suse.linux.enterprise.server":
		return f.Version == "9" || f.Version == "10"
	case "suse.linux.enterprise.desktop":
		return f.Version == "10"
	case "suse.linux.enterprise.micro":
		// SLEM 5 series has "5" and "5.y". SLEM 6 series has "6.y" only. Exclude "5" here.
		return f.Version != "5"
	case "suse.linux.enterprise":
		// suse.linux.enterprise 11, 12, and 15 have "-sp<minor>" format, and 16 has ".<minor>" format in filenames for service packs.
		if strings.Contains(f.Version, "-sp") || strings.Contains(f.Version, ".") {
			return false
		}
		return true
	default:
		return false
	}
}

func ParseFileName(name string) (*FileName, error) {
	if !strings.HasSuffix(name, ".xml.gz") {
		return nil, errors.Errorf("unexpected suffix. expects: %q, received: %q", ".xml.gz", name)
	}

	stem := strings.TrimSuffix(name, ".xml.gz")
	variant := VariantNone
	switch {
	case strings.HasSuffix(stem, "-affected"):
		variant = VariantAffected
		stem = strings.TrimSuffix(stem, "-affected")
	case strings.HasSuffix(stem, "-patch"):
		variant = VariantPatch
		stem = strings.TrimSuffix(stem, "-patch")
	}

	os, version, err := splitOSVersion(stem)
	if err != nil {
		return nil, errors.Wrap(err, "split os and version")
	}

	if os == "" {
		return nil, nil
	}
	return &FileName{Raw: name, OS: os, Version: version, Variant: variant}, nil
}

func splitOSVersion(stem string) (string, string, error) {
	// Longest-first to avoid matching "suse.linux.enterprise" before ".server" etc.
	osPrefixes := []string{
		"suse.linux.enterprise.desktop",
		"suse.linux.enterprise.server",
		"suse.linux.enterprise.micro",
		"suse.linux.enterprise",
		"opensuse.leap.micro",
		"opensuse.leap",
		"opensuse",
	}

	for _, osname := range osPrefixes {
		prefix := fmt.Sprintf("%s.", osname)
		if !strings.HasPrefix(stem, prefix) {
			continue
		}
		version := strings.TrimPrefix(stem, prefix)
		if version == "" {
			return "", "", errors.Errorf("missing version. stem: %q", stem)
		}
		return osname, version, nil
	}

	return "", "", nil
}
