// Package officec2r fetches "Release notes for Microsoft 365 Apps security
// updates", the page MSRC CVRF points Office Click-to-Run products at instead
// of giving a fixed build. Each dated entry lists the builds released per
// update channel and the CVEs fixed in them.
//
// The page is generated from markdown in a private repository
// (MicrosoftDocs/OfficeDocs-OfficeUpdates-pr), so the rendered HTML is the only
// public form of the data. Its layout may drift: any element or line that does
// not fit the structure described in parse is an error rather than skipped.
package officec2r

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/filepath"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates"

type options struct {
	dataURL string
	dir     string
	retry   int

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
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

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(opts ...Option) error {
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "microsoft", "office-c2r"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Microsoft Office Click-to-Run Security Updates")

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient)).Get(options.dataURL)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", options.dataURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	rs, err := parse(resp.Body)
	if err != nil {
		return errors.Wrap(err, "parse")
	}

	seen := make(map[string]string)
	for _, r := range rs {
		d, err := time.Parse("January 2, 2006", r.Date)
		if err != nil {
			return errors.Wrapf(err, "unexpected date format. expected: %q, actual: %q", "January 2, 2006", r.Date)
		}
		name := d.Format("2006-01-02")
		if prev, ok := seen[name]; ok {
			return errors.Errorf("unexpected duplicate release date. %q and %q are both %s", prev, r.ID, name)
		}
		seen[name] = r.ID

		p, err := utilfilepath.Join(options.dir, d.Format("2006"), fmt.Sprintf("%s.json", name))
		if err != nil {
			return errors.Wrap(err, "join")
		}
		if err := util.Write(p, r); err != nil {
			return errors.Wrapf(err, "write %s", p)
		}
	}

	return nil
}

// buildRE matches one line of an entry paragraph, e.g.
// "Monthly Enterprise Channel: Version 2609 (Build 20430.20180)" or
// "Monthly Enterprise Channel: Version 2206 (Build 15330.20298 rolled back)".
var buildRE = regexp.MustCompile(`^(\S.*?): Version (\d{4}) \(Build (\d+\.\d+)(?: ([^()]+))?\)$`)

// parse reads the article body (div.content). Up to the first h2 it is an
// introduction and is ignored. From there on it must be a sequence of
//
//	h2 (the entry date), one p (build lines separated by <br>, or a sentence
//	stating there are no updates), then any number of h3 (application) + ul
//	(CVE list) pairs
//
// and anything else is an error.
func parse(r io.Reader) ([]Release, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	// The page title sits in a div.content of its own; the article body is the
	// one holding the entry headings.
	content := doc.Find("main div.content").FilterFunction(func(_ int, s *goquery.Selection) bool {
		return s.ChildrenFiltered("h2").Length() > 0
	})
	if content.Length() != 1 {
		return nil, errors.Errorf("unexpected number of div.content with h2 in main. expected: %d, actual: %d", 1, content.Length())
	}

	var (
		rs        []Release
		paragraph bool // the current entry already has its paragraph
		list      bool // the current section already has its list
	)
	for n := range content.Nodes[0].ChildNodes() {
		switch n.Type {
		case html.ElementNode:
		case html.TextNode:
			if strings.TrimSpace(n.Data) != "" && len(rs) > 0 {
				return nil, errors.Errorf("unexpected text %q in %q", n.Data, rs[len(rs)-1].Date)
			}
			continue
		default:
			continue
		}

		if n.DataAtom == atom.H2 {
			id := attr(n, "id")
			date := collapse(text(n))
			if id == "" || date == "" {
				return nil, errors.Errorf("unexpected h2. expected: id and text, actual: id=%q, text=%q", id, date)
			}
			rs = append(rs, Release{ID: id, Date: date})
			paragraph, list = false, false
			continue
		}
		if len(rs) == 0 {
			continue
		}
		cur := &rs[len(rs)-1]

		switch n.DataAtom {
		case atom.P:
			if paragraph || len(cur.Sections) > 0 {
				return nil, errors.Errorf("unexpected p in %q. expected: one p right after h2", cur.Date)
			}
			paragraph = true
			builds, description, err := parseParagraph(n)
			if err != nil {
				return nil, errors.Wrapf(err, "parse paragraph of %q", cur.Date)
			}
			cur.Builds, cur.Description = builds, description
		case atom.H3:
			if !paragraph {
				return nil, errors.Errorf("unexpected h3 in %q. expected: p before h3", cur.Date)
			}
			name := collapse(text(n))
			if name == "" {
				return nil, errors.Errorf("unexpected empty h3 in %q", cur.Date)
			}
			cur.Sections = append(cur.Sections, Section{Name: name})
			list = false
		case atom.Ul:
			if len(cur.Sections) == 0 || list {
				return nil, errors.Errorf("unexpected ul in %q. expected: one ul right after h3", cur.Date)
			}
			list = true
			items, err := parseList(n)
			if err != nil {
				return nil, errors.Wrapf(err, "parse list %q of %q", cur.Sections[len(cur.Sections)-1].Name, cur.Date)
			}
			cur.Sections[len(cur.Sections)-1].Items = items
		default:
			return nil, errors.Errorf("unexpected element <%s> in %q. expected: %q", n.Data, cur.Date, []string{"h2", "p", "h3", "ul"})
		}
	}

	if len(rs) == 0 {
		return nil, errors.New("no release entry (h2) found in div.content")
	}
	for _, r := range rs {
		if len(r.Builds) == 0 && r.Description == "" {
			return nil, errors.Errorf("unexpected entry %q. expected: a paragraph of builds or a description", r.Date)
		}
		if len(r.Builds) == 0 && len(r.Sections) > 0 {
			return nil, errors.Errorf("unexpected entry %q. expected: builds for an entry listing fixes", r.Date)
		}
	}

	return rs, nil
}

// parseParagraph splits the entry paragraph at <br>. Either every line is a
// build line, or the paragraph is a single sentence naming no build.
func parseParagraph(p *html.Node) ([]Build, string, error) {
	var (
		lines []string
		sb    strings.Builder
	)
	for c := range p.ChildNodes() {
		switch {
		case c.Type == html.TextNode:
			sb.WriteString(c.Data)
		case c.Type == html.ElementNode && c.DataAtom == atom.Br:
			lines = append(lines, collapse(sb.String()))
			sb.Reset()
		default:
			return nil, "", errors.Errorf("unexpected node %q in paragraph. expected: text and <br>", c.Data)
		}
	}
	lines = append(lines, collapse(sb.String()))

	var builds []Build
	for _, l := range lines {
		if l == "" {
			continue
		}
		m := buildRE.FindStringSubmatch(l)
		if m == nil {
			if len(lines) == 1 && !strings.Contains(l, "Version") && !strings.Contains(l, "Build") {
				return nil, l, nil
			}
			return nil, "", errors.Errorf("unexpected build line. expected: %q, actual: %q", "<Channel>: Version <dddd> (Build <d+>.<d+>[ <note>])", l)
		}
		builds = append(builds, Build{Channel: m[1], Version: m[2], Build: m[3], Note: m[4]})
	}
	if len(builds) == 0 {
		return nil, "", errors.New("unexpected empty paragraph")
	}
	return builds, "", nil
}

func parseList(ul *html.Node) ([]Item, error) {
	var items []Item
	for c := range ul.ChildNodes() {
		switch {
		case c.Type == html.TextNode:
			if strings.TrimSpace(c.Data) != "" {
				return nil, errors.Errorf("unexpected text %q in ul", c.Data)
			}
		case c.Type == html.ElementNode && c.DataAtom == atom.Li:
			item := Item{Text: collapse(text(c))}
			if item.Text == "" {
				return nil, errors.New("unexpected empty li")
			}
			for d := range c.Descendants() {
				if d.Type != html.ElementNode || d.DataAtom != atom.A {
					continue
				}
				href := attr(d, "href")
				if href == "" {
					return nil, errors.Errorf("unexpected link without href in %q", item.Text)
				}
				item.Links = append(item.Links, Link{Text: collapse(text(d)), URL: href})
			}
			items = append(items, item)
		case c.Type == html.CommentNode:
		default:
			return nil, errors.Errorf("unexpected node %q in ul. expected: li", c.Data)
		}
	}
	return items, nil
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val
		}
	}
	return ""
}

func text(n *html.Node) string {
	var sb strings.Builder
	for d := range n.Descendants() {
		if d.Type == html.TextNode {
			sb.WriteString(d.Data)
		}
	}
	return sb.String()
}

func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
