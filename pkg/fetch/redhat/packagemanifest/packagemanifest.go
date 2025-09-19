package packagemanifest

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const urlTemplate = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%d/html-single/package_manifest/index"

type options struct {
	majors      []int
	retry       int
	urlTemplate string
	dir         string
}

type Option interface {
	apply(*options)
}

type majorsOption []int

func (m majorsOption) apply(o *options) {
	o.majors = m
}

func WithMajors(majors ...int) Option {
	return majorsOption(majors)
}

type retryOption int

func (r retryOption) apply(o *options) {
	o.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

type urlTemplateOption string

func (u urlTemplateOption) apply(o *options) {
	o.urlTemplate = string(u)
}

func WithURLTemplate(format string) Option {
	return urlTemplateOption(format)
}

type dirOption string

func (d dirOption) apply(o *options) {
	o.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type Package struct {
	Package             string `json:"package"`
	License             string `json:"license,omitempty"`
	CompatibilityLevel  string `json:"compatibility_level,omitempty"`
	MinorReleaseVersion string `json:"minor_release_version,omitempty"`
}

type packageTable struct {
	Major      int       `json:"major,omitempty"`
	Index      int       `json:"index"`
	Type       string    `json:"type"`
	Repository string    `json:"repository,omitempty"`
	Packages   []Package `json:"packages"`
	Source     string    `json:"source"`
}

type Module struct {
	Module             string   `json:"module"`
	Stream             string   `json:"stream"`
	CompatibilityLevel string   `json:"compatibility_level,omitempty"`
	Packages           []string `json:"packages"`
}

type moduleTable struct {
	Major      int      `json:"major,omitempty"`
	Index      int      `json:"index"`
	Type       string   `json:"type"`
	Repository string   `json:"repository,omitempty"`
	Modules    []Module `json:"modules"`
	Source     string   `json:"source"`
}

func Fetch(opts ...Option) error {
	opt := &options{
		majors:      []int{8, 9, 10},
		retry:       3,
		urlTemplate: urlTemplate,
		dir:         filepath.Join(util.CacheDir(), "fetch", "redhat", "packagemanifest"),
	}

	for _, o := range opts {
		o.apply(opt)
	}

	if err := util.RemoveAll(opt.dir); err != nil {
		return errors.Wrapf(err, "remove %s", opt.dir)
	}

	for _, major := range opt.majors {
		log.Printf("[INFO] Fetch RHEL %d Package Manifest", major)
		u := fmt.Sprintf(opt.urlTemplate, major)

		resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opt.retry)).Get(u)
		if err != nil {
			return errors.Wrapf(err, "get document. URL: %s", u)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "parse html")
		}

		for idx, s := range doc.Find("table").EachIter() {
			if err := writeTable(major, idx, s, opt.dir, u); err != nil {
				return errors.Wrapf(err, "write table. major: %d, index: %d", major, idx)
			}
		}

	}
	return nil
}

func writeTable(major int, idx int, s *goquery.Selection, rootDir, source string) error {
	var headers []string
	s.Find("thead tr").Last().Find("th").Each(func(_ int, h *goquery.Selection) {
		headers = append(headers, h.Text())
	})
	if len(headers) == 0 {
		return errors.New("no table header")
	}

	switch headers[0] {
	case "Package":
		var ps []Package
		for _, tr := range s.Find("tbody tr").EachIter() {
			p := Package{}
			for i, c := range tr.Find("td").EachIter() {
				if len(headers) <= i {
					return errors.Errorf("unexpected cell index. type: package, expected: < %d, actual: %d", len(headers), i)
				}
				t := strings.TrimSpace(c.Text())
				switch headers[i] {
				case "Package":
					p.Package = t
				case "License":
					p.License = t
				case "Application Compatibility Level":
					p.CompatibilityLevel = t
				case fmt.Sprintf("RHEL %d Minor Release Version", major):
					p.MinorReleaseVersion = t
				default:
					// RHEL10's "2.6. The Resilient Storage add-on" table has
					// "RHEL 9 Minor Release Version" column header even though it's for RHEL 10.
					if major != 10 || idx != 7 {
						return errors.Errorf("unexpected header. type: package, header: %q", headers[i])
					}
				}
			}

			if p.Package == "" {
				return errors.Errorf("invalid package information. package: %+v", p)
			}
			ps = append(ps, p)
		}
		t := packageTable{
			Major:      major,
			Index:      idx,
			Repository: findRepo(s),
			Type:       "package",
			Packages:   ps,
			Source:     source,
		}
		if err := util.Write(filepath.Join(rootDir, fmt.Sprintf("%d", major), fmt.Sprintf("%d-package.json", idx)), t); err != nil {
			return errors.Wrapf(err, "write package table. file: %s", filepath.Join(rootDir, fmt.Sprintf("%d", major), fmt.Sprintf("%d-package.json", idx)))
		}

	case "Module":
		var ms []Module
		for _, tr := range s.Find("tbody tr").EachIter() {
			m := Module{}
			for i, c := range tr.Find("td").EachIter() {
				if len(headers) <= i {
					return errors.Errorf("unexpected cell index. type: module, expected: <%d, actual: %d", len(headers), i)
				}
				t := strings.TrimSpace(c.Text())
				switch headers[i] {
				case "Module":
					m.Module = t
				case "Stream":
					m.Stream = t
				case "Packages":
					var ps []string
					for p := range strings.SplitSeq(t, ",") {
						pp := strings.TrimSpace(p)
						if pp != "" {
							ps = append(ps, pp)
						}
					}
					m.Packages = ps
				case "Application Compatibility Level":
					m.CompatibilityLevel = t
				default:
					return errors.Errorf("unexpected header. type: module, header: %q", headers[i])
				}
			}

			if m.Module == "" || m.Stream == "" || len(m.Packages) == 0 {
				return errors.Errorf("invalid module information. module: %+v", m)
			}
			ms = append(ms, m)
		}
		t := moduleTable{
			Major:      major,
			Index:      idx,
			Type:       "module",
			Repository: findRepo(s),
			Modules:    ms,
			Source:     source,
		}
		if err := util.Write(filepath.Join(rootDir, fmt.Sprintf("%d", major), fmt.Sprintf("%d-module.json", idx)), t); err != nil {
			return errors.Wrapf(err, "write module table. file: %s", filepath.Join(rootDir, fmt.Sprintf("%d", major), fmt.Sprintf("%d-module.json", idx)))
		}

	default:
		return errors.Errorf("unexpected first header. expected: %q,  actual: %q", []string{"Package", "Module"}, headers[0])
	}

	return nil
}

func findRepo(s *goquery.Selection) string {
	title := func() string {
		cur := s
		for cur.Length() > 0 {
			for _, p := range cur.PrevAll().EachIter() {
				if p.HasClass("title") {
					return strings.TrimSpace(p.Text())
				}
				hs := p.Find(".title")
				if hs.Length() > 0 {
					last := hs.Last()
					return strings.TrimSpace(last.Text())
				}
			}
			cur = cur.Parent()
		}
		return ""
	}()

	switch {
	case strings.Contains(title, "BaseOS"):
		return "BaseOS"
	case strings.Contains(title, "AppStream"):
		return "AppStream"
	case strings.Contains(title, "Supplementary"):
		return "Supplementary"
	default:
		return ""
	}
}
