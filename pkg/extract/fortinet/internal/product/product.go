// Package product resolves Fortinet product names (shared between the CSAF and
// CVRF extractors) to CPEs.
package product

import (
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
)

// ToCPE returns the CPE 2.3 formatted string (wildcard version) for a Fortinet
// product name, or ("", false) when the name is not in the table. Callers
// should log and record unknown names rather than fabricate a CPE.
func ToCPE(name string) (string, bool) {
	cpe, ok := nameToCPE[strings.TrimSpace(name)]
	return cpe, ok
}

// BakeVersion returns cpe with its version attribute set to the concrete
// version string (dots/hyphens escaped per CPE WFN rules), e.g.
// ("cpe:2.3:o:fortinet:fortios:*:...", "7.4.3") -> the same CPE pinned to
// 7.4.3. Mirrors go-cve-dictionary's fetcher/fortinet version handling.
func BakeVersion(cpe, version string) (string, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", errors.Wrapf(err, "unbind %q to WFN", cpe)
	}
	if err := wfn.Set("version", strings.NewReplacer(".", `\.`, "-", `\-`).Replace(version)); err != nil {
		return "", errors.Wrapf(err, "set version %q", version)
	}
	return naming.BindToFS(wfn), nil
}
