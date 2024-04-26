package freebsd

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/freebsd"
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
		dir: filepath.Join(util.CacheDir(), "extract", "", ""),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract FreeBSD")
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

		var fetched freebsd.Vuln
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

func extract(fetched freebsd.Vuln) types.Data {
	if fetched.Cancelled != nil {
		return types.Data{
			ID:         fetched.Vid,
			DataSource: source.FreeBSD,
		}
	}

	reflen := 1
	reflen += len(fetched.References.URL)
	reflen += len(fetched.References.FreebsdSA)
	reflen += len(fetched.References.FreebsdPR)
	reflen += len(fetched.References.Mlist)
	reflen += len(fetched.References.BID)
	reflen += len(fetched.References.CertSA)
	reflen += len(fetched.References.CertVU)
	reflen += len(fetched.References.USCertTA)

	rs := make([]reference.Reference, 0, reflen)
	rs = append(rs, reference.Reference{
		Source: "vuxml.freebsd.org",
		URL:    fmt.Sprintf("https://www.vuxml.org/freebsd/%s.html", fetched.Vid),
	})
	for _, u := range fetched.References.URL {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			URL:    u,
		})
	}
	for _, a := range fetched.References.FreebsdSA {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			URL:    fmt.Sprintf("https://www.freebsd.org/security/advisories/FreeBSD-%s.asc", a),
		},
		)
	}
	for _, a := range fetched.References.FreebsdPR {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			URL:    fmt.Sprintf("https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=%s", strings.TrimPrefix(a, "ports/")),
		})
	}
	for _, m := range fetched.References.Mlist {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			URL:    m.Text,
		})
	}
	for _, b := range fetched.References.BID {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			// The URL i.e. http://www.securityfocus.com/bid/12615 is 503 at 2024-04-21,
			// we should use, for example, WebArchive.org waybackmachine.
			URL: fmt.Sprintf("http://www.securityfocus.com/bid/%s", b),
		})
	}
	for _, c := range fetched.References.CertSA {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			// The URL http://www.cert.org/advisories/CA-2004-01.html is redirected to not very detailed page,
			// Because there is only one certsa tag at 2004, leave it as it is.
			URL: fmt.Sprintf("http://www.cert.org/advisories/%s.html", c),
		})
	}
	for _, c := range fetched.References.CertVU {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			URL:    fmt.Sprintf("https://www.kb.cert.org/vuls/id/%s", c),
		})
	}
	for _, u := range fetched.References.USCertTA {
		rs = append(rs, reference.Reference{
			Source: "vuxml.freebsd.org",
			// The URL i.e. http://www.uscert.gov/cas/techalerts/TA07-199A.html is 503 at 2024-04-21,
			// we should use, for example, WebArchive.org waybackmachine.
			URL: fmt.Sprintf("http://www.uscert.gov/cas/techalerts/%s.html", u),
		})
	}

	vs := make([]types.Vulnerability, 0, len(fetched.References.Cvename))
	for _, c := range fetched.References.Cvename {
		vs = append(vs, types.Vulnerability{
			ID: c,
			References: []reference.Reference{{
				Source: "vuxml.freebsd.org",
				URL:    fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", c),
			}}})
	}

	ds := make([]detection.Detection, 0, len(fetched.Affects))
	for _, a := range fetched.Affects {
		for _, n := range a.Name {
			rs := make([]detection.Range, 0, len(a.Range))
			for _, r := range a.Range {
				rs = append(rs, detection.Range{Equal: r.Eq, LessThan: r.Lt, LessEqual: r.Le, GreaterThan: r.Gt, GreaterEqual: r.Ge})
			}
			ds = append(ds, detection.Detection{
				Ecosystem:  detection.EcosystemTypeFreeBSD,
				Vulnerable: true,
				Package:    detection.Package{Name: n},
				Affected: &detection.Affected{
					Type:  detection.RangeTypeVersion,
					Range: rs,
				}})
		}
	}
	return types.Data{
		ID: fetched.Vid,
		Advisories: []types.Advisory{{
			ID:          fetched.Vid,
			Title:       fetched.Topic,
			Description: fetched.Description.Text,
			Severity:    []severity.Severity{},
			References:  rs,
			Published:   utiltime.Parse([]string{"2006-01-02"}, fetched.Dates.Entry),
			Modified:    utiltime.Parse([]string{"2006-01-02"}, fetched.Dates.Modified),
		}},
		Vulnerabilities: vs,
		Detection:       ds,
		DataSource:      source.FreeBSD,
	}
}
