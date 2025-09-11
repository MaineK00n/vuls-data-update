package packagemanifest

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

// The Red Hat Package Manifest documentation provides HTML tables listing repositories / streams.
// We scrape each table and emit one JSON file per table.
// Supported major versions are configurable. Default: 8,9,10.

const baseDocURL = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%d/html-single/package_manifest/index"

// options holds Fetch options.
type options struct {
	majors []int
	retry  int
	base   string // format string with %d placeholder
	dir    string
}

type Option interface {
	apply(*options)
}

type majorsOption []int

func (m majorsOption) apply(o *options) {
	o.majors = m
}

// WithMajors sets target RHEL major versions.
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

type baseOption string

func (b baseOption) apply(o *options) {
	o.base = string(b)
}

// WithBase allows overriding base URL format (must contain %d)
func WithBase(format string) Option {
	return baseOption(format)
}

type dirOption string

func (d dirOption) apply(o *options) {
	o.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

// Table represents a scraped HTML table.
type Table struct {
	Title   string              `json:"title"`
	ID      string              `json:"id"`
	Headers []string            `json:"headers"`
	Rows    []map[string]string `json:"rows"`
	Source  string              `json:"source"`
}

// Package represents a row in a package table (first header == "package").
type Package struct {
	Package                       string `json:"package"`
	License                       string `json:"license,omitempty"`
	ApplicationCompatibilityLevel string `json:"application_compatibility_level,omitempty"`
	RHEL9MinorReleaseVersion      string `json:"rhel_9_minor_release_version,omitempty"`
	RHEL10MinorReleaseVersion     string `json:"rhel_10_minor_release_version,omitempty"`
}

// PackageTable is a specialized table containing packages.
type PackageTable struct {
	Title    string    `json:"title"`
	ID       string    `json:"id"`
	Packages []Package `json:"packages"`
	Source   string    `json:"source"`
}

// Module represents a row in a module table (first header == "module").
type Module struct {
	Module                        string   `json:"module"`
	Stream                        string   `json:"stream"`
	ApplicationCompatibilityLevel string   `json:"application_compatibility_level,omitempty"`
	Packages                      []string `json:"packages"`
}

// ModuleTable is a specialized table containing modules.
type ModuleTable struct {
	Title   string   `json:"title"`
	ID      string   `json:"id"`
	Modules []Module `json:"modules"`
	Source  string   `json:"source"`
}

// Fetch scrapes package manifest tables for specified RHEL major versions.
func Fetch(opts ...Option) error {
	opt := &options{
		majors: []int{8, 9, 10},
		retry:  3,
		base:   baseDocURL,
		dir:    filepath.Join(util.CacheDir(), "fetch", "redhat", "packagemanifest"),
	}
	for _, o := range opts {
		o.apply(opt)
	}

	if err := util.RemoveAll(opt.dir); err != nil {
		return errors.Wrapf(err, "remove %s", opt.dir)
	}

	for _, major := range opt.majors {
		log.Printf("[INFO] Fetch RHEL %d Package Manifest", major)
		u := fmt.Sprintf(opt.base, major)

		// Retrieve & parse
		doc, err := func() (*goquery.Document, error) {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opt.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "get document")
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}
			d, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				return nil, errors.Wrap(err, "parse html")
			}
			return d, nil
		}()
		if err != nil {
			return errors.Wrapf(err, "fetch rhel %d package manifest", major)
		}

		// Extract tables.
		if err := extractAndWriteTables(doc, major, opt.dir, u); err != nil {
			return errors.Wrapf(err, "extract tables rhel %d", major)
		}
	}
	return nil
}

var whitespace = regexp.MustCompile(`\s+`)

func extractAndWriteTables(doc *goquery.Document, major int, rootDir, source string) error {
	// Strategy: find all tables inside the article/body; for each table, determine caption (if present) or preceding heading text.
	// Provide stable ID: use table id attribute if present else normalized title index.
	// Rows: map header->cell text. If duplicate headers, append index suffix.

	// gather heading anchors for context lookup (heading -> cumulative index in DOM) if needed.
	// Simpler: when table has no caption, look backward for nearest h2/h3/h4.
	tableIndex := 0
	doc.Find("table").Each(func(i int, s *goquery.Selection) {
		var id string
		// Title detection (improved): caption -> nearest heading (h1-h6) traversing previous siblings recursively up the ancestor chain.
		title := findNearestHeading(s)
		if capSel := s.Find("caption"); capSel.Length() > 0 { // caption has precedence if present
			captionText := strings.TrimSpace(capSel.Text())
			if captionText != "" {
				title = captionText
			}
		}

		id, _ = s.Attr("id")
		if id == "" {
			id = fmt.Sprintf("table-%d", tableIndex)
		}
		tableIndex++

		// headers
		var headers []string
		s.Find("thead tr").Last().Find("th").Each(func(_ int, h *goquery.Selection) {
			headers = append(headers, normalizeHeader(h.Text()))
		})
		if len(headers) == 0 {
			s.Find("tr").First().Find("th,td").Each(func(_ int, h *goquery.Selection) { headers = append(headers, normalizeHeader(h.Text())) })
		}
		firstHeader := ""
		if len(headers) > 0 {
			firstHeader = headers[0]
		}

		// build rows
		var rows []map[string]string
		s.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
			cells := tr.Find("th,td")
			if cells.Length() == 0 {
				return
			}
			row := make(map[string]string)
			cells.Each(func(ci int, c *goquery.Selection) {
				text := strings.TrimSpace(whitespace.ReplaceAllString(c.Text(), " "))
				h := headerAt(headers, ci)
				row[h] = text
			})
			if len(row) > 0 {
				rows = append(rows, row)
			}
		})
		if len(rows) == 0 {
			// fallback include rows if tbody absent
			s.Find("tr").Each(func(_ int, tr *goquery.Selection) {
				if tr.Find("th,td").Length() == 0 || tr.ParentsFiltered("thead").Length() > 0 {
					return
				}
				row := make(map[string]string)
				tr.Find("th,td").Each(func(ci int, c *goquery.Selection) {
					text := strings.TrimSpace(whitespace.ReplaceAllString(c.Text(), " "))
					h := headerAt(headers, ci)
					row[h] = text
				})
				if len(row) > 0 {
					rows = append(rows, row)
				}
			})
		}

		// Specialized handling for package/module tables based on first header
		if firstHeader == "package" {
			var pkgs []Package
			for _, r := range rows {
				pkgs = append(pkgs, Package{
					Package:                       r["package"],
					License:                       r["license"],
					ApplicationCompatibilityLevel: r["application_compatibility_level"],
					RHEL9MinorReleaseVersion:      r["rhel_9_minor_release_version"],
					RHEL10MinorReleaseVersion:     r["rhel_10_minor_release_version"],
				})
			}
			pt := PackageTable{Title: title, ID: id, Packages: pkgs, Source: source}
			if err := util.Write(filepath.Join(rootDir, fmt.Sprintf("%d", major), fmt.Sprintf("package-%s.json", sanitizeFilename(id))), pt); err != nil {
				log.Printf("[ERROR] write package table %s: %v", id, err)
			}
			return
		}
		if firstHeader == "module" {
			var mods []Module
			for _, r := range rows {
				var list []string
				if pkgsField := r["packages"]; pkgsField != "" {
					for _, p := range strings.Split(pkgsField, ",") {
						pp := strings.TrimSpace(p)
						if pp != "" {
							list = append(list, pp)
						}
					}
				}
				mods = append(mods, Module{
					Module:                        r["module"],
					Stream:                        r["stream"],
					ApplicationCompatibilityLevel: r["application_compatibility_level"],
					Packages:                      list,
				})
			}
			mt := ModuleTable{Title: title, ID: id, Modules: mods, Source: source}
			if err := util.Write(filepath.Join(rootDir, fmt.Sprintf("%d", major), fmt.Sprintf("module-%s.json", sanitizeFilename(id))), mt); err != nil {
				log.Printf("[ERROR] write module table %s: %v", id, err)
			}
			return
		}

		// write file
		t := Table{Title: title, ID: id, Headers: headers, Rows: rows, Source: source}
		if err := util.Write(filepath.Join(rootDir, fmt.Sprintf("%d", major), fmt.Sprintf("%s.json", sanitizeFilename(id))), t); err != nil {
			log.Printf("[ERROR] write table %s: %v", id, err)
		}
	})
	return nil
}

// findNearestHeading finds the closest preceding heading (h1-h6) relative to the table.
// It walks up the ancestor chain; for each ancestor it inspects previous siblings (closest first),
// searching inside them (depth-first) for the last heading. Returns empty string if not found.
func findNearestHeading(s *goquery.Selection) string {
	headingsSelector := "h1,h2,h3,h4,h5,h6"
	// current node whose previous siblings we inspect
	cur := s
	for cur.Length() > 0 {
		// iterate previous siblings in reverse order (closest first)
		prevs := []*goquery.Selection{}
		cur.PrevAll().Each(func(_ int, ps *goquery.Selection) { prevs = append(prevs, ps) })
		for i := 0; i < len(prevs)/2; i++ { // reverse slice
			prevs[i], prevs[len(prevs)-1-i] = prevs[len(prevs)-1-i], prevs[i]
		}
		for _, p := range prevs {
			// direct heading sibling
			if goquery.NodeName(p) == "h1" || goquery.NodeName(p) == "h2" || goquery.NodeName(p) == "h3" || goquery.NodeName(p) == "h4" || goquery.NodeName(p) == "h5" || goquery.NodeName(p) == "h6" {
				return strings.TrimSpace(p.Text())
			}
			// search inside previous sibling for headings; take the last one (closest context)
			hs := p.Find(headingsSelector)
			if hs.Length() > 0 {
				return strings.TrimSpace(hs.Last().Text())
			}
		}
		cur = cur.Parent()
	}
	return ""
}

func normalizeHeader(h string) string {
	return strings.TrimSpace(whitespace.ReplaceAllString(strings.ToLower(h), "_"))
}

var filenameSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	s = filenameSanitizeRe.ReplaceAllString(s, "-")
	if s == "" {
		s = "table"
	}
	return s
}

func headerAt(headers []string, idx int) string {
	if idx < len(headers) {
		return headers[idx]
	}
	return fmt.Sprintf("col_%d", idx)
}
