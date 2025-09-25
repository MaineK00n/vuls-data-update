package packagemanifest

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html-single/package_manifest/index"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(o *options) {
	o.baseURL = string(u)
}

func WithBaseURL(baseURL string) Option {
	return baseURLOption(baseURL)
}

type dirOption string

func (d dirOption) apply(o *options) {
	o.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(o *options) {
	o.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(majors []string, opts ...Option) error {
	opt := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "redhat", "package-manifest"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(opt)
	}

	if err := util.RemoveAll(opt.dir); err != nil {
		return errors.Wrapf(err, "remove %s", opt.dir)
	}

	if err := os.MkdirAll(opt.dir, 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", opt.dir)
	}
	if err := os.WriteFile(filepath.Join(opt.dir, "README.md"), []byte(`## Repository of Red Hat Package Manifest data accumulation

All the data in this repository are fetched from following pages by Red Hat, Inc.

- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html-single/package_manifest/index
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/package_manifest/index
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/package_manifest/index

### Copyright and License notice

Copyright © 2025 Red Hat, Inc.
The text of and illustrations in this document are licensed by Red Hat under a Creative Commons Attribution–Share Alike 3.0 Unported license ("CC-BY-SA"). An explanation of CC-BY-SA is available at http://creativecommons.org/licenses/by-sa/3.0/. In accordance with CC-BY-SA, if you distribute this document or an adaptation of it, you must provide the URL for the original version.
Red Hat, as the licensor of this document, waives the right to enforce, and agrees not to assert, Section 4d of CC-BY-SA to the fullest extent permitted by applicable law.
`), 0666); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(opt.dir, "README.md"))
	}

	c := utilhttp.NewClient(utilhttp.WithClientRetryMax(opt.retry))

	for _, major := range majors {
		log.Printf("[INFO] Fetch RHEL %s Package Manifest", major)
		u := fmt.Sprintf(opt.baseURL, major)

		resp, err := c.Get(u)
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
			if err := writeTable(major, s, opt.dir); err != nil {
				return errors.Wrapf(err, "write table. major: %s, index: %d", major, idx)
			}
		}
	}
	return nil
}

func writeTable(major string, s *goquery.Selection, rootDir string) error {
	ref, err := findReference(s)
	if err != nil {
		return errors.Wrap(err, "find reference")
	}

	// RHEL10's "2.6. The Resilient Storage add-on" table has "RHEL 9 Minor Release Version" column header
	// even though it's for RHEL 10. The table should be removed in the future because it is deprecated in RHEL 10.
	if major == "10" && ref == "resilient-storage-addon" {
		return nil
	}

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
			cells := tr.Find("td")
			if cells.Length() != len(headers) {
				return errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
			}

			var p Package
			for i, c := range cells.EachIter() {
				t := strings.TrimSpace(c.Text())
				switch headers[i] {
				case "Package":
					p.Package = t
				case "License":
					p.License = t
				case "Application Compatibility Level":
					p.CompatibilityLevel = t
				case fmt.Sprintf("RHEL %s Minor Release Version", major):
					p.MinorReleaseVersion = t
				default:
					return errors.Errorf("unexpected header. type: package, header: %q", headers[i])
				}
			}

			if p.Package == "" {
				return errors.Errorf("invalid package information. package: %+v", p)
			}
			ps = append(ps, p)
		}

		t := PackageTable{
			Major:     major,
			Reference: ref,
			Type:      "package",
			Packages:  ps,
		}
		if err := util.Write(filepath.Join(rootDir, "package", major, fmt.Sprintf("%s.json", ref)), t); err != nil {
			return errors.Wrapf(err, "write package table. file: %s", filepath.Join(rootDir, "package", major, fmt.Sprintf("%s.json", ref)))
		}

		return nil
	case "Module":
		var ms []Module
		for _, tr := range s.Find("tbody tr").EachIter() {
			cells := tr.Find("td")
			if cells.Length() != len(headers) {
				return errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
			}

			var m Module
			for i, c := range cells.EachIter() {
				t := strings.TrimSpace(c.Text())
				switch headers[i] {
				case "Module":
					m.Module = t
				case "Stream":
					m.Stream = t
				case "Packages":
					var ps []string
					for p := range strings.SplitSeq(t, ",") {
						if pp := strings.TrimSpace(p); pp != "" {
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

		t := ModuleTable{
			Major:     major,
			Type:      "module",
			Reference: ref,
			Modules:   ms,
		}
		if err := util.Write(filepath.Join(rootDir, "module", major, fmt.Sprintf("%s.json", ref)), t); err != nil {
			return errors.Wrapf(err, "write module table. file: %s", filepath.Join(rootDir, "module", major, fmt.Sprintf("%s.json", ref)))
		}

		return nil
	default:
		return errors.Errorf("unexpected first header. expected: %q,  actual: %q", []string{"Package", "Module"}, headers[0])
	}
}

func findReference(s *goquery.Selection) (string, error) {
	title := func() *goquery.Selection {
		cur := s
		for cur.Length() > 0 {
			for _, p := range cur.PrevAll().EachIter() {
				if p.HasClass("title") {
					return p
				}
				hs := p.Find(".title")
				if hs.Length() > 0 {
					return hs.Last()
				}
			}
			cur = cur.Parent()
		}
		return nil
	}()
	if title == nil || title.Length() == 0 {
		return "", errors.New("no title found")
	}

	href, exists := title.Find("a").First().Attr("href")
	if !exists {
		return "", errors.Errorf("no anchor found. title: %+v", title)
	}

	return strings.TrimPrefix(href, "#"), nil
}
