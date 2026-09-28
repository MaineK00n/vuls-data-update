// Package exchange fetches Microsoft's Exchange Server build numbers and
// release dates -- the page listing every build Exchange has shipped.
//
// The page runs from Exchange Server 4.0 to the Subscription Edition, and 76 of
// its builds name a KB. Those are the security and hotfix updates: a cumulative
// update is a download and carries no KB, so the SUs are the only builds
// addressable that way, and they are what a scanner has to reason about.
//
// The KB is not in a column. It is the link on the product's name --
//
//	<a href="https://support.microsoft.com/help/5121574">Exchange Server 2019 CU15 Aug26SU</a>
//
// so a cell read as text alone loses it entirely. This page is the only
// structured record of several: four of eleven sampled answer "We did not find
// any results" in the Update Catalog, the August, July and June 2026 updates
// among them.
//
// One KB covers many builds. KB5000871, the March 2021 update, appears on
// twenty-five rows -- every cumulative update level of Exchange 2013, 2016 and
// 2019 that was still in support got its own patched build of the one fix. The
// rows are stored as served and matched up in extract.
//
// fetch writes <dir>/origin verbatim and then produces <dir>/raw by reading it
// back, never the HTTP response, so raw/ is reproducible from origin/ alone.
package exchange

import (
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
	"golang.org/x/net/html"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	baseURL = "https://learn.microsoft.com"

	// pagePath is the build numbers page. The name it is stored under is its
	// last segment, so origin/ stays navigable against the site it came from.
	pagePath = "/en-us/exchange/new-features/build-numbers-and-release-dates"
)

type options struct {
	baseURL string
	dir     string
	retry   int
	wait    time.Duration
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

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

// Fetch stores the page under <dir>/origin and the tables it carries under
// <dir>/raw.
func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "microsoft", "exchange"),
		retry:   3,
		wait:    1 * time.Second,
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

// fetch stores the page as served.
func (opts options) fetch() error {
	slog.Info("Fetch Microsoft Exchange Build Numbers and Release Dates")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	u, err := url.JoinPath(opts.baseURL, pagePath)
	if err != nil {
		return errors.Wrapf(err, "join %s and %s", opts.baseURL, pagePath)
	}

	if err := client.PipelineGet([]string{u}, 1, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d, url: %s", resp.StatusCode, resp.Request.URL)
		}

		bs, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "read %s", resp.Request.URL)
		}

		if err := writeOrigin(opts.dir, name(), bs); err != nil {
			return errors.Wrapf(err, "write %s", name())
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

// convert reads origin/ back and writes raw/, at the name its origin/
// counterpart has. Going through the stored bytes rather than the response is
// what lets the tree be re-derived after this parser changes.
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

		// The page is its tables. One that parses to none is not a page whose
		// history has been retired -- it keeps Exchange Server 4.0, released in
		// 1996, alongside the current release -- it is this parser having lost
		// them, and it loses them all at once. Skipping would leave raw/ empty
		// beside a full origin/ with the run green.
		if len(page.Tables) == 0 {
			return errors.Errorf("no table in %s", p)
		}

		if err := util.Write(filepath.Join(opts.dir, "raw", strings.TrimSuffix(filepath.ToSlash(rel), ".html")+".json"), page); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "raw", strings.TrimSuffix(filepath.ToSlash(rel), ".html")+".json"))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	return nil
}

// name is what the page is stored as: the last segment of its path, so origin/
// stays navigable against the site it came from.
func name() string {
	segs := strings.Split(strings.Trim(pagePath, "/"), "/")
	return segs[len(segs)-1] + ".html"
}

// writeOrigin stores content under <dir>/origin/<name> as served.
//
// Nothing derived from the response is recorded alongside it -- no fetch
// timestamp, no ETag, no status line. Those change on every run even when the
// page does not, and would turn every fetch into a diff, drowning the signal
// this tree exists to carry: that Microsoft revised the page.
func writeOrigin(dir, name string, content []byte) error {
	p := filepath.Join(dir, "origin", name)

	if err := os.MkdirAll(filepath.Dir(p), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(p))
	}

	if err := os.WriteFile(p, content, 0666); err != nil {
		return errors.Wrapf(err, "write %s", p)
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

	// Only the article body. The page chrome carries tables of its own, the
	// locale picker among them, and a heading in a banner would otherwise
	// become the heading of the first history.
	root := doc.Find("main").First()
	if root.Length() == 0 {
		root = doc.Selection
	}

	// One pass in document order over the headings and the tables together,
	// since a table's heading is its predecessor in the prose and not its
	// ancestor. Headings inside a table are skipped: being visited after their
	// own table's start tag they would otherwise be read as the next one's.
	var heading string
	root.Find("h1, h2, h3, h4, h5, h6, table").Each(func(_ int, s *goquery.Selection) {
		if goquery.NodeName(s) != "table" {
			if s.Closest("table").Length() == 0 {
				heading = text(s.Text())
			}
			return
		}

		t, ok := parseTable(s, base)
		if !ok {
			return
		}
		t.Heading = heading

		page.Tables = append(page.Tables, t)
	})

	return page, nil
}

// parseTable reads one table's column names and cells, reporting false for the
// ones that carry neither.
func parseTable(s *goquery.Selection, base *url.URL) (Table, bool) {
	var rows [][]Cell
	s.Find("tr").Each(func(_ int, tr *goquery.Selection) {
		var cells []Cell
		tr.Find("th, td").Each(func(_ int, c *goquery.Selection) {
			cells = append(cells, parseCell(c, base))
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

// parseCell reads a cell's text and the first link it carries.
//
// A line break is read as the space it stands for. Microsoft breaks two of this
// page's column names across lines -- "Build number<br>(short format)" -- and
// reading the text straight through runs them together as
// "Build number(short format)", which is not a name any reader would look for.
func parseCell(s *goquery.Selection, base *url.URL) Cell {
	var b strings.Builder

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			switch {
			case c.Type == html.TextNode:
				b.WriteString(c.Data)
			case c.Type == html.ElementNode && c.Data == "br":
				b.WriteString(" ")
			case c.Type == html.ElementNode:
				walk(c)
			}
		}
	}
	for _, n := range s.Nodes {
		walk(n)
	}

	cell := Cell{Text: text(b.String())}
	if href, ok := s.Find("a[href]").First().Attr("href"); ok {
		cell.Href = resolve(base, text(href))
	}

	return cell
}

// resolve turns a link into an address that works away from the page it was
// read on. One that cannot be parsed is kept as served rather than dropped: it
// is not this parser's to decide that Microsoft meant nothing by it.
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
