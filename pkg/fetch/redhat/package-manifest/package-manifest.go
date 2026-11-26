package packagemanifest

import (
	"bytes"
	"cmp"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/filepath"
)

// baseURL is where the pages are published: the page stored as
// origin/<path>.html is the one at <baseURL><path>.
const baseURL = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/"

var (
	// pagePath is the path of a page under baseURL: a major release, then the
	// page, in segments that hold no dot.
	pagePath     = regexp.MustCompile(`^[0-9]+(/[A-Za-z0-9_-]+)+$`)
	articleStart = regexp.MustCompile(`<article[\s>]`)
	articleEnd   = regexp.MustCompile(`</article>`)
	tableStart   = regexp.MustCompile(`<table[\s>]`)
)

type options struct {
	dir string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(o *options) {
	o.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

// Fetch writes the tables of the package manifest pages kept in origin/ under
// the output directory, after storing there the saved pages it is given.
//
// docs.redhat.com answers 403 to a client it does not take for a browser, and
// its robots.txt disallows the single-page manifests of RHEL 8 and 9, so the
// pages are saved by hand rather than fetched, and origin/ keeps them from one
// run to the next. A saved page is stored cut down to its <article> element,
// which holds the text of the document and every table, at the path of its
// URL under baseURL with ".html" added: RHEL 8 and 9 publish the manifest as
// one page, <major>/html-single/package_manifest/index, and RHEL 10 as a page
// for each repository, such as 10/plan-baseos.
func Fetch(saved []string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "fetch", "redhat", "package-manifest"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	given := make(map[string][]byte, len(saved)) // the name a page is stored under in origin/ -> the page, cut down
	from := make(map[string]string, len(saved))  // the name a page is stored under in origin/ -> the file it is saved as
	for _, s := range saved {
		name, article, err := cut(s)
		if err != nil {
			return errors.Wrapf(err, "cut %s", s)
		}
		if prev, ok := from[name]; ok {
			return errors.Errorf("duplicate page. %s and %s are both %s", prev, s, name)
		}
		given[name], from[name] = article, s
	}

	origin := filepath.Join(options.dir, "origin")
	pages, err := listPages(origin, slices.Collect(maps.Keys(given)))
	if err != nil {
		return errors.Wrapf(err, "list pages in %s", origin)
	}

	// Every table is read before anything is written, so that a run that
	// fails, on a page given or on one stored, leaves the tree as it was: a
	// page given is not stored unless the whole of origin/ reads with it.
	var tables []table
	written := make(map[string]string) // the file a table is written to -> the page it is read from
	for _, p := range pages {
		slog.Info("Read RHEL Package Manifest", slog.String("version", p.major), slog.String("page", p.path))

		bs, ok := given[p.path]
		if !ok {
			bs, err = os.ReadFile(filepath.Join(origin, filepath.FromSlash(p.path)))
			if err != nil {
				return errors.Wrapf(err, "read %s", filepath.Join(origin, filepath.FromSlash(p.path)))
			}
		}

		ts, err := readPage(p.major, bs)
		if err != nil {
			return errors.Wrapf(err, "read RHEL %s package manifest. page: %s", p.major, p.path)
		}
		for _, t := range ts {
			// A second table of the same name would be written over the
			// first, as when a release's manifest moves to new pages and the
			// old page is kept.
			if prev, ok := written[t.name]; ok {
				return errors.Errorf("duplicate table. %s is in both %s and %s", t.name, prev, p.path)
			}
			written[t.name] = p.path
			tables = append(tables, t)
		}
	}

	// EnsureWritten below requires both kinds of table. A run without one is
	// failed here too, before anything is written, so that it also leaves the
	// tree as it was.
	var npackage, nmodule int
	for _, t := range tables {
		switch t.value.(type) {
		case PackageTable:
			npackage++
		case ModuleTable:
			nmodule++
		}
	}
	if npackage == 0 || nmodule == 0 {
		return errors.Errorf("unexpected tables. expected: %s, actual: %d package and %d module tables", "a package and a module table at least", npackage, nmodule)
	}

	for _, p := range pages {
		article, ok := given[p.path]
		if !ok {
			continue
		}
		slog.Info("Store RHEL Package Manifest page", slog.String("page", p.path), slog.String("from", from[p.path]))

		path, err := utilfilepath.Join(origin, filepath.FromSlash(p.path))
		if err != nil {
			return errors.Wrap(err, "join")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
		}
		if err := os.WriteFile(path, article, 0666); err != nil {
			return errors.Wrapf(err, "write %s", path)
		}
	}

	// origin/ is the input, which no fetch can rebuild, so it is kept with
	// .git (WithKeep states the whole set). Everything else is rebuilt from
	// it.
	if err := util.RemoveAll(options.dir, util.WithKeep(".git", "origin")); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	if err := os.WriteFile(filepath.Join(options.dir, "README.md"), readme(pages), 0666); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "README.md"))
	}

	for _, t := range tables {
		path, err := utilfilepath.Join(options.dir, t.name)
		if err != nil {
			return errors.Wrap(err, "join")
		}
		if err := util.Write(path, t.value); err != nil {
			return errors.Wrapf(err, "write %s", path)
		}
	}

	// The README is written whatever the fetch got, and origin/ is kept, so
	// the tables are what must be there: a page whose tables are no longer
	// recognized would otherwise leave only those.
	if err := util.EnsureWritten(options.dir, util.WithRequire("package", "module")); err != nil {
		return errors.Wrapf(err, "ensure written %s", options.dir)
	}

	return nil
}

// cut reads the page saved at path into the name it is stored under in
// origin/, and its <article> element, byte for byte. The page's canonical link
// names its URL.
func cut(path string) (string, []byte, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return "", nil, errors.Wrapf(err, "read %s", path)
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return "", nil, errors.Wrap(err, "parse html")
	}
	links := doc.Find(`link[rel="canonical"]`)
	if links.Length() != 1 {
		return "", nil, errors.Errorf("unexpected number of canonical links. expected: %d, actual: %d", 1, links.Length())
	}
	href, _ := links.Attr("href")
	u, err := url.Parse(href)
	if err != nil {
		return "", nil, errors.Wrapf(err, "parse %q", href)
	}
	// RHEL 10's pages name localhost as the host of their canonical link, so
	// only the path is read.
	rel, ok := strings.CutPrefix(u.Path, "/en/documentation/red_hat_enterprise_linux/")
	if !ok || !pagePath.MatchString(rel) {
		return "", nil, errors.Errorf("unexpected canonical link. expected: %s, actual: %q", fmt.Sprintf("%s<major>/<page>", baseURL), href)
	}

	starts, ends := articleStart.FindAllIndex(bs, -1), articleEnd.FindAllIndex(bs, -1)
	if len(starts) != 1 || len(ends) != 1 || ends[0][0] < starts[0][0] {
		return "", nil, errors.Errorf("unexpected article element. expected: %s, actual: %d start tags and %d end tags", "one of each", len(starts), len(ends))
	}
	article := bs[starts[0][0]:ends[0][1]]
	if !tableStart.Match(article) {
		return "", nil, errors.New("no table found in the article")
	}

	return fmt.Sprintf("%s.html", rel), append(bytes.Clone(article), '\n'), nil
}

type page struct {
	major string
	path  string // relative to origin/, slash-separated, e.g. 10/plan-baseos.html
}

// listPages lists the pages stored in origin/, and those to be stored there
// under the names given, over a page of the same name.
func listPages(origin string, given []string) ([]page, error) {
	pages, err := findPages(origin)
	if err != nil {
		// No page has been stored yet, and the pages given are the first.
		if !errors.Is(err, fs.ErrNotExist) || len(given) == 0 {
			return nil, errors.Wrapf(err, "find pages in %s", origin)
		}
		pages = nil
	}

	for _, name := range given {
		if slices.ContainsFunc(pages, func(p page) bool { return p.path == name }) {
			continue
		}
		major, _, _ := strings.Cut(name, "/")
		pages = append(pages, page{major: major, path: name})
	}
	slices.SortFunc(pages, comparePages)

	return pages, nil
}

// findPages lists every .html file in each directory of dir, as a page of the
// major release the directory is named for. Anything else there fails: a page
// put anywhere else, or stored under another name, would not be read, and its
// tables would be missing without a word.
func findPages(dir string) ([]page, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", dir)
	}

	var pages []page
	for _, e := range es {
		if !e.IsDir() {
			return nil, errors.Errorf("unexpected entry. expected: %s, actual: %q", "a directory for a major release", filepath.Join(dir, e.Name()))
		}

		if err := filepath.WalkDir(filepath.Join(dir, e.Name()), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() || filepath.Ext(path) != ".html" {
				return errors.Errorf("unexpected entry. expected: %s, actual: %q", "a page, as a .html file", path)
			}

			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return errors.Wrapf(err, "rel %s", path)
			}
			pages = append(pages, page{major: e.Name(), path: filepath.ToSlash(rel)})

			return nil
		}); err != nil {
			return nil, errors.Wrapf(err, "walk %s", filepath.Join(dir, e.Name()))
		}
	}
	slices.SortFunc(pages, comparePages)

	return pages, nil
}

// comparePages orders pages by release, 8, 9, 10 rather than 10, 8, 9 (of two
// numbers, the longer is greater), then as a walk of origin/ visits them.
func comparePages(a, b page) int {
	return cmp.Or(
		cmp.Compare(len(a.major), len(b.major)),
		strings.Compare(a.major, b.major),
		slices.Compare(strings.Split(a.path, "/"), strings.Split(b.path, "/")),
	)
}

// table is a table read from a page: the name of the file it is written to,
// relative to the output directory, and what is written there.
type table struct {
	name  string
	value any
}

// readPage reads the tables of a page of the given major release.
func readPage(major string, bs []byte) ([]table, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse html")
	}

	// A page kept for its tables that holds none is not a page of the
	// manifest. cut refuses one, but origin/ can be changed by hand.
	ss := doc.Find("table")
	if ss.Length() == 0 {
		return nil, errors.New("no table found")
	}

	tables := make([]table, 0, ss.Length())
	for idx, s := range ss.EachIter() {
		name, value, err := readTable(major, s)
		if err != nil {
			return nil, errors.Wrapf(err, "read table. index: %d", idx)
		}
		tables = append(tables, table{name: name, value: value})
	}

	return tables, nil
}

func readme(pages []page) []byte {
	var b strings.Builder
	b.WriteString(`## Repository of Red Hat Package Manifest data accumulation

All the data in this repository are fetched from following pages by Red Hat, Inc.

`)
	for _, p := range pages {
		fmt.Fprintf(&b, "- %s%s\n", baseURL, strings.TrimSuffix(filepath.ToSlash(p.path), ".html"))
	}
	b.WriteString(`
docs.redhat.com refuses automated clients, so the pages are saved from a browser by hand. origin/ keeps them, each at the path of its URL and cut down to its article element, and the tables in package/ and module/ are read from them. To store pages saved again, run in this repository:

    vuls-data-update fetch redhat-package-manifest --dir . <saved page>...

### Copyright and License notice

Copyright © Red Hat, Inc.
The text of and illustrations in this document are licensed by Red Hat under a Creative Commons Attribution–Share Alike 3.0 Unported license ("CC-BY-SA"). An explanation of CC-BY-SA is available at http://creativecommons.org/licenses/by-sa/3.0/. In accordance with CC-BY-SA, if you distribute this document or an adaptation of it, you must provide the URL for the original version.
Red Hat, as the licensor of this document, waives the right to enforce, and agrees not to assert, Section 4d of CC-BY-SA to the fullest extent permitted by applicable law.

The pages in origin/ are the documents above, cut down to their article element. Those of RHEL 8 and 9 carry their Legal Notice in it. For those of RHEL 10, see https://docs.redhat.com/en/legal-notice.
`)
	return []byte(b.String())
}

// readTable reads a table into the name of the file it is written to, relative
// to the output directory, and what is written there.
func readTable(major string, s *goquery.Selection) (string, any, error) {
	ref, err := findReference(s)
	if err != nil {
		return "", nil, errors.Wrap(err, "find reference")
	}
	// The reference names the file the table is written to, in the
	// directory of its release.
	if ref == "" || strings.ContainsAny(ref, `/\`) {
		return "", nil, errors.Errorf("unexpected reference. expected: %s, actual: %q", "an id with no path separator", ref)
	}

	var headers []string
	s.Find("thead tr").Last().Find("th").Each(func(_ int, h *goquery.Selection) {
		headers = append(headers, h.Text())
	})
	if len(headers) == 0 {
		return "", nil, errors.New("no table header")
	}

	switch headers[0] {
	case "Package":
		var ps []Package
		for _, tr := range s.Find("tbody tr").EachIter() {
			cells := tr.Find("td")
			if cells.Length() != len(headers) {
				return "", nil, errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
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
					return "", nil, errors.Errorf("unexpected header. type: package, header: %q", headers[i])
				}
			}

			if p.Package == "" {
				return "", nil, errors.Errorf("invalid package information. package: %+v", p)
			}
			ps = append(ps, p)
		}

		return filepath.Join("package", major, fmt.Sprintf("%s.json", ref)), PackageTable{
			Major:     major,
			Reference: ref,
			Type:      "package",
			Packages:  ps,
		}, nil
	case "Module":
		var ms []Module
		for _, tr := range s.Find("tbody tr").EachIter() {
			cells := tr.Find("td")
			if cells.Length() != len(headers) {
				return "", nil, errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
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
					return "", nil, errors.Errorf("unexpected header. type: module, header: %q", headers[i])
				}
			}

			if m.Module == "" || m.Stream == "" || len(m.Packages) == 0 {
				return "", nil, errors.Errorf("invalid module information. module: %+v", m)
			}
			ms = append(ms, m)
		}

		return filepath.Join("module", major, fmt.Sprintf("%s.json", ref)), ModuleTable{
			Major:     major,
			Type:      "module",
			Reference: ref,
			Modules:   ms,
		}, nil
	default:
		return "", nil, errors.Errorf("unexpected first header. expected: %q,  actual: %q", []string{"Package", "Module"}, headers[0])
	}
}

// findReference names a table by the id of the part of the page that holds
// it, such as "BaseOS-repository" or "CRB-modules".
func findReference(s *goquery.Selection) (string, error) {
	// The pages of RHEL 10 are built with DITA-OT, which gives the title of a
	// topic no anchor, but ids each header cell "<topic>__entry__<n>", or
	// "<topic>__<section>__entry__<n>" for a table in a section of the topic.
	// The id of the topic, or of the section, is the one the pages of RHEL 8
	// and 9 anchor the title of the same table to.
	if id, ok := s.Find("thead tr").Last().Find("th").First().Attr("id"); ok {
		if ref, _, ok := strings.Cut(id, "__entry__"); ok {
			if i := strings.LastIndex(ref, "__"); i >= 0 {
				ref = ref[i+len("__"):]
			}
			return ref, nil
		}
	}

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

	// Only the fragment names the part: a saved page may write the anchor
	// out as a URL.
	_, ref, ok := strings.Cut(href, "#")
	if !ok {
		return "", errors.Errorf("unexpected anchor. expected: %s, actual: %q", "a link to a fragment", href)
	}

	return ref, nil
}
