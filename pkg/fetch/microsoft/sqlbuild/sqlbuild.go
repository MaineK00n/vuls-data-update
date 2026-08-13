// Package sqlbuild fetches Microsoft's SQL Server build-versions article --
// "Download and install the latest updates for SQL Server" -- from the docs
// repository it is authored in.
//
// The article lists, per product version, every build SQL Server has shipped:
// the build number, the service pack it belongs to, what kind of update it is
// and the KB. It runs from SQL Server 2005 to the current release, 584 KBs, and
// the Update Catalog no longer serves most of them.
//
// It is fetched as Markdown from MicrosoftDocs/SupportArticles-docs rather than
// as the rendered page, because the repository is public and keeps the article's
// history. A row Microsoft removes is recoverable from git afterwards, which the
// rendered page cannot offer at all -- and recovering what has been removed is
// the whole reason this source exists.
//
// The per-version articles under sqlserver-<year>/build-versions.md were
// measured against this one and add nothing: their KB sets are identical to it,
// version for version, all six of them, and what they carry beyond it is the
// sqlservr.exe and msmdsrv.exe file versions, which no chain is ordered by. This
// article also covers SQL Server 2012, 2008 R2, 2008 and 2005, which have no
// per-version article at all -- 197 KBs that exist nowhere else in the set.
//
// Being hand-authored Markdown, it is not always well formed: one row of the
// 2016 article has lost its leading pipe, and the rendered page shows the row
// because the docs pipeline forgives it. The table reader forgives it too, and
// says so, so that a row held together by leniency is a thing someone can go and
// look at rather than a silent repair.
//
// fetch writes <dir>/origin verbatim and then produces <dir>/raw by reading it
// back, never the HTTP response, so raw/ is reproducible from origin/ alone.
package sqlbuild

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	baseURL = "https://raw.githubusercontent.com/MicrosoftDocs/SupportArticles-docs/main"

	// articlePath is the article's path in the docs repository, which is both
	// where it is fetched from and where its history is read.
	articlePath = "support/sql/releases/download-and-install-latest-updates.md"
)

var (
	// separatorPattern is the row of dashes under a Markdown table's header. It
	// is the only row that is not content.
	separatorPattern = regexp.MustCompile(`^:?-{2,}:?$`)

	headingPattern = regexp.MustCompile(`^#{1,6}\s+(.*)$`)

	// linkPattern is a Markdown link. Only the first of a cell is taken: a cell
	// naming two links names two things, and which of them is the cell's own
	// address is not this parser's to decide.
	linkPattern = regexp.MustCompile(`\[([^\]]*)\]\(([^)]*)\)`)

	// markupPattern is the emphasis and the line breaks Microsoft writes inside
	// cells, which are presentation and not content.
	markupPattern = regexp.MustCompile(`\*\*|<br\s*/?>|__`)
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

// Fetch stores the article under <dir>/origin and the tables it carries under
// <dir>/raw.
func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "microsoft", "sqlbuild"),
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

// fetch stores the article as served.
func (opts options) fetch() error {
	slog.Info("Fetch Microsoft SQL Server Build Versions")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	u, err := url.JoinPath(opts.baseURL, articlePath)
	if err != nil {
		return errors.Wrapf(err, "join %s and %s", opts.baseURL, articlePath)
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

		if err := writeOrigin(opts.dir, articlePath, bs); err != nil {
			return errors.Wrapf(err, "write %s", articlePath)
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

// convert reads origin/ back and writes raw/, at the path its origin/
// counterpart has. Going through the stored bytes rather than the response is
// what lets the tree be re-derived after this parser changes.
func (opts options) convert() error {
	slog.Info("Convert origin to raw")

	root := filepath.Join(opts.dir, "origin")

	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(p) != ".md" {
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return errors.Wrapf(err, "rel %s", p)
		}
		rel = filepath.ToSlash(rel)

		bs, err := os.ReadFile(p)
		if err != nil {
			return errors.Wrapf(err, "read %s", p)
		}

		a := parseArticle(string(bs), rel)

		// The article is its tables. One that parses to none is not an article
		// whose tables have been retired -- it lists builds back to SQL Server
		// 6.5, released in 1996 -- it is this parser having lost them, and it
		// loses them all at once. Skipping would leave raw/ empty beside a full
		// origin/ with the run green.
		if len(a.Tables) == 0 {
			return errors.Errorf("no table in %s", p)
		}

		if err := util.Write(filepath.Join(opts.dir, "raw", fmt.Sprintf("%s.json", strings.TrimSuffix(rel, ".md"))), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "raw", fmt.Sprintf("%s.json", strings.TrimSuffix(rel, ".md"))))
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
// timestamp, no ETag, no commit. Those change on every run even when the article
// does not, and would turn every fetch into a diff, drowning the signal this
// tree exists to carry: that Microsoft revised the article.
func writeOrigin(dir, name string, content []byte) error {
	path := filepath.Join(dir, "origin", filepath.FromSlash(name))

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
	}

	if err := os.WriteFile(path, content, 0666); err != nil {
		return errors.Wrapf(err, "write %s", path)
	}

	return nil
}

// parseArticle reads an article's tables, each under the heading it follows.
func parseArticle(doc, path string) Article {
	a := Article{Path: path}

	var heading string
	// The table being read, as an index rather than a pointer: appending the
	// next one may move the slice out from under a pointer into it.
	table := -1
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimRight(line, "\r")

		if m := headingPattern.FindStringSubmatch(line); m != nil {
			heading = strings.TrimSpace(m[1])
			table = -1
			continue
		}

		cells, ok := parseRow(line, table >= 0)
		if !ok {
			table = -1
			continue
		}
		if cells == nil {
			// The dashes under a header. They say how the columns align and
			// nothing about what is in them.
			continue
		}

		if table < 0 {
			a.Tables = append(a.Tables, Table{Heading: heading, Header: texts(cells)})
			table = len(a.Tables) - 1
			continue
		}
		a.Tables[table].Rows = append(a.Tables[table].Rows, cells)
	}

	// A table of nothing but a header is not a table. The article carries one:
	// its opening summary is a header row Microsoft never filled in.
	a.Tables = slices.DeleteFunc(a.Tables, func(t Table) bool { return len(t.Rows) == 0 })

	return a
}

// parseRow reads one line as a table row, reporting false for the lines that
// are not one and a nil row for the separator under a header.
//
// A row is recognised by its leading pipe, except inside a table, where a line
// carrying pipes is taken as a row without one. Microsoft has served such a row
// -- the SQL Server 2016 article has one that lost its leading pipe -- and the
// docs pipeline renders it as part of the table, so a reader that stopped there
// would end the table early and read the rest of it as a new one, header and
// all. Being inside a table is what makes it safe: the prose between tables is
// never taken this way.
func parseRow(line string, inTable bool) ([]Cell, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, false
	}

	if !strings.HasPrefix(trimmed, "|") {
		if !inTable || !strings.Contains(trimmed, "|") {
			return nil, false
		}
		slog.Warn("table row without a leading pipe", slog.String("row", trimmed))
	}

	fields := strings.Split(strings.Trim(trimmed, "|"), "|")

	separator := true
	for _, f := range fields {
		if !separatorPattern.MatchString(strings.TrimSpace(f)) {
			separator = false
			break
		}
	}
	if separator {
		return nil, true
	}

	cells := make([]Cell, 0, len(fields))
	for _, f := range fields {
		cells = append(cells, parseCell(f))
	}

	return cells, true
}

// parseCell reads a cell's text and the first link it carries.
func parseCell(s string) Cell {
	var href string
	if m := linkPattern.FindStringSubmatch(s); m != nil {
		href = strings.TrimSpace(m[2])
	}

	// The link's text stands in for the link, which is what the cell reads as.
	text := linkPattern.ReplaceAllString(s, "$1")
	text = markupPattern.ReplaceAllString(text, " ")

	return Cell{Text: strings.Join(strings.Fields(text), " "), Href: href}
}

func texts(cells []Cell) []string {
	out := make([]string, 0, len(cells))
	for _, c := range cells {
		out = append(out, c.Text)
	}
	return out
}
