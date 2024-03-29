package arch

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/arch"
)

type options struct {
	dir string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "arch"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Arch Linux")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var fetched arch.VulnerabilityGroup
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		extracted := extract(fetched)

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json", extracted.ID)), extracted); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}

func extract(fetched arch.VulnerabilityGroup) types.Data {
	extracted := types.Data{
		ID: fetched.Name,
		Advisories: []types.Advisory{{
			ID: fetched.Name,
			Severity: []severity.Severity{{
				Type:   severity.SeverityTypeVendor,
				Source: "security.archlinux.org",
				Vendor: &fetched.Severity,
			}},
			References: []reference.Reference{{
				Source: "security.archlinux.org",
				URL:    fmt.Sprintf("https://security.archlinux.org/%s", fetched.Name),
			}},
		}},
	}

	if fetched.Ticket != nil {
		extracted.Advisories[0].References = append(extracted.Advisories[0].References, reference.Reference{
			Source: "security.archlinux.org",
			URL:    fmt.Sprintf("https://bugs.archlinux.org/task/%s", *fetched.Ticket),
		})
	}

	for _, a := range fetched.Advisories {
		extracted.Advisories = append(extracted.Advisories, types.Advisory{
			ID: a,
			References: []reference.Reference{{
				Source: "security.archlinux.org",
				URL:    fmt.Sprintf("https://security.archlinux.org/%s", a),
			}},
		})
	}

	for _, i := range fetched.Issues {
		extracted.Vulnerabilities = append(extracted.Vulnerabilities, types.Vulnerability{
			ID: i,
			References: []reference.Reference{{
				Source: "security.archlinux.org",
				URL:    fmt.Sprintf("https://security.archlinux.org/%s", i),
			}},
		})
	}

	affected := detection.Affected{
		Type:  detection.RangeTypePacman,
		Range: []detection.Range{{LessEqual: fetched.Affected}},
	}
	if fetched.Fixed != nil {
		affected = detection.Affected{
			Type:  detection.RangeTypePacman,
			Range: []detection.Range{{LessThan: *fetched.Fixed}},
			Fixed: []string{*fetched.Fixed},
		}
	}

	for _, p := range fetched.Packages {
		extracted.Detection = append(extracted.Detection, func() detection.Detection {
			return detection.Detection{
				Ecosystem:  detection.EcosystemTypeArch,
				Vulnerable: true,
				Package: detection.Package{
					Name: p,
				},
				Affected: &affected,
			}
		}())
	}

	return extracted
}
