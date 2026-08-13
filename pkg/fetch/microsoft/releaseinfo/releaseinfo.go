// Package releaseinfo fetches Microsoft's Windows release-information pages --
// the release-health tables on learn.microsoft.com for Windows 10, Windows 11
// and Windows Server.
//
// Each page lists, per release, every monthly update it has shipped: the OS
// build, the availability date, the release-cadence letter and the KB. The
// Update Catalog drops an update outright once Microsoft expires it and
// wsusscn2.cab drops it too; these tables keep it. KB3205386, KB5014710 and
// KB4601331 all answer "We did not find any results" in the catalog and are all
// still listed here.
//
// The servicing articles cover the same ground and are the fuller source -- 944
// of the 974 KBs on the Windows 10 page are in the os/windows-10 sidebar. What
// this adds is the 30 that are not, and what none of the articles carry:
//
//   - Twenty-one of the thirty are the updates from 2015-07-29 to 2016-01-27.
//     Their articles exist, but are titled "Cumulative update for Windows 10
//     Version 1511: December 8, 2015" and name no KB anywhere, so extract drops
//     them for want of a key. This is where that key is.
//
//   - The release-cadence letter, as a column. B is the second Tuesday and is
//     the line the following month builds on; C and D are the optional previews
//     of the weeks after it, and OOB is out-of-band. The servicing extractor
//     infers the same split from the release date falling on a second Tuesday,
//     which is a reading of the calendar rather than of what Microsoft said.
//
//   - The hotpatch calendars, which say which update is a Baseline (Restart)
//     and which is a Hotpatch. Nothing else states that, and it is not a detail:
//     a hotpatch line rebases on its quarterly baseline instead of running on
//     from the month before, so ordering those updates as one chain with the
//     ordinary cumulative ones is wrong.
//
//   - The OS build in a column of its own, rather than in a title Microsoft
//     writes at least four ways.
//
// fetch writes <dir>/origin verbatim and then produces <dir>/raw by reading it
// back, never the HTTP response, so raw/ is reproducible from origin/ alone.
// The tables are stored as served and are not read apart here; that is extract's
// job.
package releaseinfo

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://learn.microsoft.com"

// pages are the release-information pages, by the name each is stored under.
//
// Windows Server has a page of its own even though its builds are the ones the
// Windows 10 and 11 pages already list -- 26100 is Windows Server 2025 here and
// Windows 11 24H2 there, each shipping its own KBs at revisions the other also
// ships. Storing them apart is what keeps the two from being read as one line.
var pages = []struct {
	name string
	path string
}{
	{name: "windows-10", path: "/en-us/windows/release-health/release-information"},
	{name: "windows-11", path: "/en-us/windows/release-health/windows11-release-information"},
	{name: "windows-server", path: "/en-us/windows/release-health/windows-server-release-info"},
}

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithBaseURL(url string) Option {
	return baseURLOption(url)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

// Fetch stores the release-information pages under <dir>/origin and the tables
// they carry under <dir>/raw.
func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "microsoft", "releaseinfo"),
		retry:       3,
		concurrency: 1,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	if err := options.convert(); err != nil {
		return errors.Wrap(err, "convert")
	}

	return nil
}

// fetch stores each page as served.
//
// Three requests to one host, so the pipeline runs one at a time: there is
// nothing here for concurrency to shorten, and learn.microsoft.com has no
// reason to be asked three times at once for it.
func (opts options) fetch() error {
	slog.Info("Fetch Microsoft Release Information")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	names := make(map[string]string, len(pages))
	us := make([]string, 0, len(pages))
	for _, p := range pages {
		u, err := url.JoinPath(opts.baseURL, p.path)
		if err != nil {
			return errors.Wrapf(err, "join %s and %s", opts.baseURL, p.path)
		}
		names[u] = p.name
		us = append(us, u)
	}

	if err := client.PipelineGet(us, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d, url: %s", resp.StatusCode, resp.Request.URL)
		}

		bs, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "read %s", resp.Request.URL)
		}

		// The name is looked up by the URL the request was built with, not the
		// one it landed on: learn.microsoft.com appends a ?view= to some paths
		// on redirect, and a page stored under a name that moves with it would
		// double the tree the first time it does.
		name, ok := names[resp.Request.URL.String()]
		if !ok {
			return errors.Errorf("unexpected url. expected: one of %q, actual: %q", us, resp.Request.URL)
		}

		if err := writeOrigin(opts.dir, fmt.Sprintf("%s.html", name), bs); err != nil {
			return errors.Wrapf(err, "write %s", fmt.Sprintf("%s.html", name))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

// convert reads origin/ back and writes raw/, one file per stored page so that
// which JSON came from which HTML is a matter of the name. Going through the
// stored bytes rather than the response is what lets the tree be re-derived
// after this parser changes.
func (opts options) convert() error {
	slog.Info("Convert origin to raw")

	root := filepath.Join(opts.dir, "origin")

	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(p) != ".html" {
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return errors.Wrapf(err, "rel %s", p)
		}

		f, err := os.Open(p)
		if err != nil {
			return errors.Wrapf(err, "open %s", p)
		}
		defer f.Close()

		page, err := parsePage(f)
		if err != nil {
			return errors.Wrapf(err, "parse %s", p)
		}

		// A release-information page is its tables. One that parses to none is
		// not a page whose tables have all been retired -- Microsoft has kept
		// every Windows 10 release back to 1507 through the version's end of
		// support and past it -- it is this parser having lost them, and it
		// loses them for every page at once. Skipping would leave raw/ empty
		// beside a full origin/ with the run green.
		if len(page.Tables) == 0 {
			return errors.Errorf("no table in %s", p)
		}

		if err := util.Write(filepath.Join(opts.dir, "raw", fmt.Sprintf("%s.json", strings.TrimSuffix(rel, ".html"))), page); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "raw", fmt.Sprintf("%s.json", strings.TrimSuffix(rel, ".html"))))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	return nil
}

// writeOrigin stores content under <dir>/origin/<name> as served.
//
// Nothing derived from the response is recorded alongside it -- no fetch
// timestamp, no ETag, no status line. Those change on every run even when the
// page does not, and would turn every fetch into a diff, drowning the signal
// this tree exists to carry: that Microsoft revised the page.
func writeOrigin(dir, name string, content []byte) error {
	path := filepath.Join(dir, "origin", name)

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
	}

	if err := os.WriteFile(path, content, 0666); err != nil {
		return errors.Wrapf(err, "write %s", path)
	}

	return nil
}

// parsePage reads a stored page for its canonical link and its tables.
func parsePage(r io.Reader) (Page, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return Page{}, errors.Wrap(err, "new document")
	}

	var page Page
	var base *url.URL
	if u, ok := doc.Find(`link[rel="canonical"]`).First().Attr("href"); ok {
		page.URL = text(u)
		base, _ = url.Parse(page.URL)
	}

	// Only the article body. The page chrome carries tables of its own -- the
	// locale picker among them -- and a <strong> in a banner would otherwise
	// become the label of the first release history.
	root := doc.Find("main").First()
	if root.Length() == 0 {
		root = doc.Selection
	}

	// One pass in document order over the labels and the tables together, since
	// a table's label is not its ancestor or its sibling: Microsoft leaves it a
	// <strong> loose in the prose above. Labels inside a table are skipped --
	// they are cell emphasis, and being visited after their own table's start
	// tag they would otherwise be read as the next table's label.
	var label string
	root.Find("strong, h1, h2, h3, h4, h5, h6, table").Each(func(_ int, s *goquery.Selection) {
		if goquery.NodeName(s) != "table" {
			if s.Closest("table").Length() == 0 {
				label = text(s.Text())
			}
			return
		}

		t, ok := parseTable(s, base)
		if !ok {
			return
		}
		t.Label = label

		page.Tables = append(page.Tables, t)
	})

	return page, nil
}

// parseTable reads one table's column names and cells, reporting false for the
// ones that carry neither.
//
// The header is the first row whatever it is marked up with. Microsoft writes
// these tables both ways -- some open with a row of th, others with a thead --
// and a table read as all body would put its column names in raw/ as data.
func parseTable(s *goquery.Selection, base *url.URL) (Table, bool) {
	var rows [][]Cell
	s.Find("tr").Each(func(_ int, tr *goquery.Selection) {
		var cells []Cell
		tr.Find("th, td").Each(func(_ int, c *goquery.Selection) {
			cell := Cell{Text: text(c.Text())}
			if href, ok := c.Find("a[href]").First().Attr("href"); ok {
				cell.Href = resolve(base, text(href))
			}
			cells = append(cells, cell)
		})
		if len(cells) == 0 {
			return
		}
		rows = append(rows, cells)
	})

	if len(rows) < 2 {
		return Table{}, false
	}

	header := make([]string, 0, len(rows[0]))
	for _, c := range rows[0] {
		header = append(header, c.Text)
	}

	return Table{Header: header, Rows: rows[1:]}, true
}

// resolve turns a cell's href into an address that works away from the page it
// was read on. An href that cannot be parsed is kept as served rather than
// dropped: it is not this parser's to decide that Microsoft meant nothing by it.
func resolve(base *url.URL, href string) string {
	if href == "" || base == nil {
		return href
	}
	ref, err := url.Parse(href)
	if err != nil {
		return href
	}
	return base.ResolveReference(ref).String()
}

// text normalizes the whitespace HTML is free to write however it likes.
// goquery has already resolved the entities.
func text(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
