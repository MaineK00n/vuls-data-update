package securityreleases

import (
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"golang.org/x/net/html"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://support.apple.com/en-us/100100"

// Known upstream state, so that only expected pages may be skipped; anything
// outside these fails the fetch loudly.
//
// The retired-host links and the removed articles together cost about 75
// pre-2011 advisories: their list rows survive, but no advisories/<id>.json
// is written for them, which downstream stages should treat as normal. The
// contents survive on the Wayback Machine and could be recovered in a
// follow-up with a committed table of pinned snapshot URLs; see
// https://github.com/MaineK00n/vuls-data-update/pull/914#discussion_r3727277181
// for the verified plan.
var (
	// inlineAdvisoryPageIDs are the archive index pages that inline pre-2005
	// advisory content directly instead of listing links to per-release pages.
	// They are parsed as advisories; any other page yielding no releases is an
	// error.
	inlineAdvisoryPageIDs = []string{
		"101682", // Apple security updates (03 Oct 2003 to 11 Jan 2005)
		"104191", // Apple security updates (August 2003 and earlier)
	}

	// retiredHosts are the hosts that links on pre-2011 archive pages are known
	// to point at but that no longer serve content. Links to them are skipped;
	// links to any other unexpected host are an error.
	retiredHosts = []string{"docs.info.apple.com", "www.info.apple.com", "info.apple.com"}

	// removableArticleIDPattern matches the legacy article ID forms (4-digit HT
	// and 5-digit TA numbers, all pre-2011 releases) that are known to have been
	// removed upstream. Only these may respond 404; a 404 on any other article
	// is an error.
	removableArticleIDPattern = regexp.MustCompile(`^(HT[0-9]{4}|TA[0-9]{5})$`)
)

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

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "apple", "security-releases"),
		retry:       3,
		concurrency: 5,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Apple Security Releases")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	root, err := url.Parse(options.baseURL)
	if err != nil {
		return errors.Wrapf(err, "parse %s", options.baseURL)
	}

	pages, err := options.fetchIndex(client, root)
	if err != nil {
		return errors.Wrap(err, "fetch index")
	}

	advisories, err := options.fetchLists(client, root, pages)
	if err != nil {
		return errors.Wrap(err, "fetch lists")
	}

	if err := options.fetchAdvisories(client, advisories); err != nil {
		return errors.Wrap(err, "fetch advisories")
	}

	return nil
}

// fetchIndex answers one question: which list pages exist? It fetches the
// security releases index page, which authoritatively lists every archive
// page, validates it, and returns the index itself together with the
// archive page URLs. The index is then crawled again by fetchLists as an
// ordinary list page; the duplicate fetch is one request out of roughly
// 1,240 per run, paid so that list-page handling exists in exactly one
// place.
func (opts options) fetchIndex(client *utilhttp.Client, root *url.URL) ([]*url.URL, error) {
	slog.Info("Fetch security releases index", slog.String("url", root.String()))

	resp, err := client.Get(root.String())
	if err != nil {
		return nil, errors.Wrapf(err, "get %s", root)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d. URL: %s", resp.StatusCode, root)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse html")
	}

	list, err := parseList(doc, articleID(resp.Request.URL), resp.Request.URL)
	if err != nil {
		return nil, errors.Wrapf(err, "parse list. URL: %s", root)
	}
	if len(list.Releases) == 0 {
		return nil, errors.Errorf("no releases found in list page. URL: %s", root)
	}

	archives, err := parseArchives(doc, list.ID, resp.Request.URL, root)
	if err != nil {
		return nil, errors.Wrapf(err, "parse archives. URL: %s", root)
	}
	// the index authoritatively lists every archive page; none matching
	// would mean upstream restructured the navigation, and following it
	// silently would drop all historical release rows
	if len(archives) == 0 {
		return nil, errors.Errorf("no archive pages found in index page. URL: %s", root)
	}

	return append([]*url.URL{root}, archives...), nil
}

// fetchLists fetches the list pages — the index and its archive pages —
// level by level with PipelineGet and returns the advisory URLs of their
// release rows. The index already lists every archive page, so the crawl
// normally ends after one level; following the pages' own navigation links
// is kept only as a safety net for a future archive that is linked solely
// from another archive. Each page is
// written as lists/<canonical id>.json; the pre-2005 pages that inline
// advisory content instead of listing links are written as
// advisories/<id>.json instead.
func (opts options) fetchLists(client *utilhttp.Client, root *url.URL, pages []*url.URL) (map[string]*url.URL, error) {
	// the crawl is expected to end after two levels (the list pages, then
	// their alias links); processed prevents revisits, so a deeper graph
	// means upstream keeps producing links to fresh article IDs in a way
	// this crawler does not understand
	const maxLevel = 5

	// parsed is one fetched and parsed page of a level. advisory is set only
	// for the pre-2005 inline archive pages.
	type parsed struct {
		requested *url.URL
		final     *url.URL
		list      List
		archives  []*url.URL
		advisory  *Advisory
	}

	processed := make(map[string]struct{})
	advisories := make(map[string]*url.URL)
	level := nextLevel(pages, processed, nil)
	for n := 1; len(level) > 0; n++ {
		if n > maxLevel {
			return nil, errors.Errorf("archive crawl did not converge within %d levels", maxLevel)
		}

		slog.Info("Fetch security releases lists", slog.Int("count", len(level)))

		us := make([]string, 0, len(level))
		for _, u := range level {
			us = append(us, u.String())
		}

		// the callback does only per-page pure work — status check, parse —
		// and hands the few-KB result over; each body is closed as soon as
		// it is parsed. mutating state shared across the level (processed,
		// advisories, next) and writing files stays sequential below, so it
		// needs no synchronization. aliases of already processed pages are
		// parsed here just to be discarded below (~20 pages per run): not
		// because a parse is cheap, but so the callback stays a pure
		// function of the response instead of silently depending on
		// processed not being written mid-level; the wasted parses are
		// milliseconds against the network round trips
		pageChan := make(chan parsed, len(us))
		if err := client.PipelineGet(us, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
			defer resp.Body.Close()

			requested, final := originalURL(resp), resp.Request.URL

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d. URL: %s", resp.StatusCode, requested)
			}

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				return errors.Wrap(err, "parse html")
			}

			// lists are keyed by the canonical (redirect-resolved) article
			// ID, unlike advisories, whose file names keep the linked ID for
			// the join with list rows
			list, err := parseList(doc, articleID(final), final)
			if err != nil {
				return errors.Wrapf(err, "parse list. URL: %s", requested)
			}
			archives, err := parseArchives(doc, list.ID, final, root)
			if err != nil {
				return errors.Wrapf(err, "parse archives. URL: %s", requested)
			}
			page := parsed{requested: requested, final: final, list: list, archives: archives}

			if len(list.Releases) == 0 {
				if !slices.Contains(inlineAdvisoryPageIDs, list.ID) {
					return errors.Errorf("no releases found in list page. URL: %s", requested)
				}
				advisory, err := parseAdvisory(doc, list.ID, final.String())
				if err != nil {
					return errors.Wrapf(err, "parse advisory. URL: %s", requested)
				}
				page.advisory = &advisory
			}

			pageChan <- page

			return nil
		}); err != nil {
			return nil, errors.Wrap(err, "pipeline get")
		}
		close(pageChan)

		// the channel drains in completion order, which is not deterministic,
		// but no output depends on it: aliases resolving to the same page
		// carry identical content, so whichever is interpreted first writes
		// the same file, and duplicate advisory links agree on the article
		// ID, which is all the advisories map keeps
		var next []*url.URL
		for page := range pageChan {
			// an alias of an already processed page, e.g. the legacy hub
			// article kb/HT201222 linked from older lists redirects to the
			// current index en-us/100100
			if _, ok := processed[articleID(page.final)]; ok {
				processed[articleID(page.requested)] = struct{}{}
				continue
			}
			processed[articleID(page.requested)] = struct{}{}
			processed[articleID(page.final)] = struct{}{}

			next = nextLevel(page.archives, processed, next)

			if page.advisory != nil {
				if err := util.Write(filepath.Join(opts.dir, "advisories", fmt.Sprintf("%s.json", page.advisory.ID)), page.advisory); err != nil {
					return nil, errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "advisories", fmt.Sprintf("%s.json", page.advisory.ID)))
				}
				continue
			}

			if err := util.Write(filepath.Join(opts.dir, "lists", fmt.Sprintf("%s.json", page.list.ID)), page.list); err != nil {
				return nil, errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "lists", fmt.Sprintf("%s.json", page.list.ID)))
			}

			as, err := advisoryURLs(page.list, root)
			if err != nil {
				return nil, errors.Wrap(err, "collect advisory urls")
			}
			for id, u := range as {
				if _, ok := advisories[id]; !ok {
					advisories[id] = u
				}
			}
		}
		level = next
	}
	return advisories, nil
}

// nextLevel appends the archive URLs that are neither processed nor already
// queued to level.
func nextLevel(archives []*url.URL, processed map[string]struct{}, level []*url.URL) []*url.URL {
	for _, a := range archives {
		if _, ok := processed[articleID(a)]; ok {
			continue
		}
		if slices.ContainsFunc(level, func(u *url.URL) bool { return articleID(u) == articleID(a) }) {
			continue
		}
		level = append(level, a)
	}
	return level
}

// advisoryURLs collects the advisory URLs the release rows of a list link
// to, keyed by the linked article ID.
func advisoryURLs(list List, root *url.URL) (map[string]*url.URL, error) {
	advisories := make(map[string]*url.URL)
	for _, r := range list.Releases {
		if r.URL == "" {
			continue
		}
		ru, err := url.Parse(r.URL)
		if err != nil {
			return nil, errors.Wrapf(err, "parse release link %s. list: %s", r.URL, list.ID)
		}
		if ru.Host != root.Host {
			if !slices.Contains(retiredHosts, ru.Host) {
				return nil, errors.Errorf("unexpected release link host. expected: %q, actual: %q. URL: %s", root.Host, ru.Host, r.URL)
			}
			// nothing to fetch; the link is still recorded in the list
			continue
		}
		// pre-2015 lists link http://; fetch https:// directly to avoid a redirect hop
		ru.Scheme = root.Scheme
		if _, ok := advisories[articleID(ru)]; !ok {
			advisories[articleID(ru)] = ru
		}
	}
	return advisories, nil
}

// fetchAdvisories fetches the per-release security content pages and writes
// each as advisories/<id>.json. IDs are taken from the URL as linked from the
// lists, so that list rows and advisory files can be joined; pages that have
// been removed upstream (mostly releases before 2011) are skipped.
func (opts options) fetchAdvisories(client *utilhttp.Client, advisories map[string]*url.URL) error {
	us := make([]string, 0, len(advisories))
	for _, id := range slices.Sorted(maps.Keys(advisories)) {
		us = append(us, advisories[id].String())
	}

	slog.Info("Fetch security release advisories", slog.Int("count", len(us)))
	return client.PipelineGet(us, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusNotFound:
			_, _ = io.Copy(io.Discard, resp.Body)
			if !removableArticleIDPattern.MatchString(articleID(originalURL(resp))) {
				return errors.Errorf("unexpected not found response. only articles matching %q are known to be removed upstream. URL: %s", removableArticleIDPattern, originalURL(resp))
			}
			// removed upstream; the release row referencing it is still recorded in the list
			return nil
		default:
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d. URL: %s", resp.StatusCode, originalURL(resp))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "parse html")
		}

		id := articleID(originalURL(resp))
		advisory, err := parseAdvisory(doc, id, resp.Request.URL.String())
		if err != nil {
			return errors.Wrapf(err, "parse advisory. URL: %s", originalURL(resp))
		}

		if err := util.Write(filepath.Join(opts.dir, "advisories", fmt.Sprintf("%s.json", id)), advisory); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "advisories", fmt.Sprintf("%s.json", id)))
		}
		return nil
	})
}

// articleID returns the support article ID of a page URL,
// e.g. "128067" for https://support.apple.com/en-us/128067,
// "HT205636" for https://support.apple.com/kb/HT205636.
func articleID(u *url.URL) string {
	return path.Base(u.Path)
}

// originalURL returns the URL the request chain started from, walking back
// through redirects.
func originalURL(resp *http.Response) *url.URL {
	req := resp.Request
	for req.Response != nil && req.Response.Request != nil {
		req = req.Response.Request
	}
	return req.URL
}

// block is a content-level element of a support page: a heading, paragraph,
// note, list or table, in document order.
type block struct {
	name string // "h1".."h6", "p", "note", "ul", "table"
	sel  *goquery.Selection
}

// blocks collects content blocks under s, descending through wrapper elements
// but not into the returned blocks themselves. It does not descend into list
// items: callers handle "ul" blocks themselves, calling blocks(li) per item,
// which returns an empty slice for items that only hold inline content.
func blocks(s *goquery.Selection) []block {
	var bs []block
	var walk func(s *goquery.Selection)
	walk = func(s *goquery.Selection) {
		for _, c := range s.Children().EachIter() {
			switch n := goquery.NodeName(c); n {
			case "h1", "h2", "h3", "h4", "h5", "h6":
				bs = append(bs, block{name: n, sel: c})
			case "p":
				bs = append(bs, block{name: "p", sel: c})
			case "ul", "ol":
				bs = append(bs, block{name: "ul", sel: c})
			case "table":
				bs = append(bs, block{name: "table", sel: c})
			case "div":
				if c.HasClass("note") {
					bs = append(bs, block{name: "note", sel: c})
					continue
				}
				walk(c)
			case "script", "style", "noscript":
			default:
				walk(c)
			}
		}
	}
	walk(s)
	return bs
}

// normText returns the text of s with non-breaking spaces replaced by spaces,
// runs of spaces collapsed, and empty lines removed.
func normText(s *goquery.Selection) string {
	var lines []string
	for l := range strings.SplitSeq(strings.ReplaceAll(s.Text(), "\u00a0", " "), "\n") {
		if l := strings.Join(strings.Fields(l), " "); l != "" {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// isBoldParagraph reports whether p is a paragraph whose entire text is bold.
// Such paragraphs are used as component headings on older advisory pages
// instead of <h3>.
func isBoldParagraph(p *goquery.Selection) bool {
	t := normText(p)
	return t != "" && t == normText(p.Find("b, strong"))
}

// contentRoot returns the content region of a support page.
func contentRoot(doc *goquery.Document) (*goquery.Selection, error) {
	// replace <br> with newlines so that adjacent lines do not run together
	for _, br := range doc.Find("br").EachIter() {
		br.ReplaceWithNodes(&html.Node{Type: html.TextNode, Data: "\n"})
	}

	s := doc.Find("div#sections")
	if s.Length() == 0 {
		return nil, errors.New("no div#sections found")
	}
	return s, nil
}

func parseList(doc *goquery.Document, id string, pageURL *url.URL) (List, error) {
	s, err := contentRoot(doc)
	if err != nil {
		return List{}, errors.Wrap(err, "find content root")
	}

	list := List{ID: id, URL: pageURL.String()}
	var pendingList bool
	for _, b := range blocks(s) {
		switch b.name {
		case "h1":
			if list.Title == "" {
				list.Title = normText(b.sel)
			}
		case "table":
			if err := list.parseTable(b.sel, pageURL); err != nil {
				return List{}, errors.Wrap(err, "parse table")
			}
		case "p":
			if strings.HasPrefix(normText(b.sel), "Name and information link") {
				pendingList = true
			}
		case "ul":
			if !pendingList {
				continue
			}
			pendingList = false
			if err := list.parseListItems(b.sel, pageURL); err != nil {
				return List{}, errors.Wrap(err, "parse list items")
			}
		default:
		}
	}

	return list, nil
}

// parseArchives collects the "Apple security updates" navigation links of a
// list page, which point at other archive pages.
func parseArchives(doc *goquery.Document, id string, pageURL, root *url.URL) ([]*url.URL, error) {
	s, err := contentRoot(doc)
	if err != nil {
		return nil, errors.Wrap(err, "find content root")
	}

	var archives []*url.URL
	for _, a := range s.Find("a").EachIter() {
		if !strings.HasPrefix(normText(a), "Apple security updates") {
			continue
		}
		href, ok := a.Attr("href")
		if !ok {
			continue
		}
		u, err := pageURL.Parse(href)
		if err != nil {
			return nil, errors.Wrapf(err, "parse archive link %s. list: %s", href, id)
		}
		if u.Host != root.Host {
			if !slices.Contains(retiredHosts, u.Host) {
				return nil, errors.Errorf("unexpected archive link host. expected: %q, actual: %q. URL: %s", root.Host, u.Host, u)
			}
			// nav links to the retired info.apple.com on pre-2011 pages
			continue
		}
		// pre-2015 lists link http://; fetch https:// directly to avoid a redirect hop
		u.Scheme = root.Scheme
		archives = append(archives, u)
	}

	return archives, nil
}

func (l *List) parseTable(tab *goquery.Selection, pageURL *url.URL) error {
	trs := tab.Find("tr")
	if trs.Length() == 0 {
		return errors.New("no rows found")
	}

	// newer pages use <th> for the header row, older pages a <td><b>...</b></td> row
	ths := trs.First().Find("th")
	if ths.Length() == 0 {
		ths = trs.First().Find("td")
	}
	headers := make([]string, 0, ths.Length())
	for _, th := range ths.EachIter() {
		headers = append(headers, normText(th))
	}
	if len(headers) != 3 || !strings.HasPrefix(headers[0], "Name and information link") || (headers[1] != "Available for" && headers[1] != "Released for") || headers[2] != "Release date" {
		return errors.Errorf("unexpected table headers. expected: %q, actual: %q", []string{"Name and information link", "Available for | Released for", "Release date"}, headers)
	}

	for _, tr := range trs.Slice(1, trs.Length()).EachIter() {
		tds := tr.Find("td")
		if tds.Length() != len(headers) {
			return errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), tds.Length())
		}

		r := Release{
			AvailableFor: normText(tds.Eq(1)),
			ReleaseDate:  normText(tds.Eq(2)),
		}

		if ps := tds.Eq(0).Find("p"); ps.Length() > 0 {
			r.Name = normText(ps.First())
			for _, p := range ps.Slice(1, ps.Length()).EachIter() {
				if t := normText(p); t != "" {
					r.Notes = append(r.Notes, t)
				}
			}
		} else {
			r.Name = normText(tds.Eq(0))
		}

		if href, ok := tds.Eq(0).Find("a").First().Attr("href"); ok {
			u, err := pageURL.Parse(href)
			if err != nil {
				return errors.Wrapf(err, "parse release link %s. list: %s", href, l.ID)
			}
			r.URL = u.String()
		}

		l.Releases = append(l.Releases, r)
	}
	return nil
}

func (l *List) parseListItems(ul *goquery.Selection, pageURL *url.URL) error {
	for _, li := range ul.ChildrenFiltered("li").EachIter() {
		var r Release
		if a := li.Find("a").First(); a.Length() > 0 {
			r.Name = normText(a)
			if href, ok := a.Attr("href"); ok {
				u, err := pageURL.Parse(href)
				if err != nil {
					return errors.Wrapf(err, "parse release link %s. list: %s", href, l.ID)
				}
				r.URL = u.String()
			}
			li = li.Clone()
			li.Find("a").First().Remove()
			r.Text = normText(li)
		} else {
			r.Name = normText(li)
		}
		l.Releases = append(l.Releases, r)
	}
	return nil
}

func parseAdvisory(doc *goquery.Document, id, pageURL string) (Advisory, error) {
	s, err := contentRoot(doc)
	if err != nil {
		return Advisory{}, errors.Wrap(err, "find content root")
	}

	advisory := Advisory{ID: id, URL: pageURL}
	var (
		section Section
		entry   Entry
	)
	flushEntry := func() {
		if !entry.isEmpty() {
			section.Entries = append(section.Entries, entry)
		}
		entry = Entry{}
	}
	flushSection := func() {
		flushEntry()
		if section.Name != "" || len(section.Entries) > 0 {
			advisory.Sections = append(advisory.Sections, section)
		}
		section = Section{}
	}

	var handle func(b block) error
	handle = func(b block) error {
		switch b.name {
		case "h1":
			if advisory.Title == "" {
				advisory.Title = normText(b.sel)
				return nil
			}
			flushSection()
			section.Name = normText(b.sel)
		case "h2":
			flushSection()
			section.Name = normText(b.sel)
		case "h3", "h4", "h5", "h6":
			flushEntry()
			entry.Component = normText(b.sel)
		case "p":
			if isBoldParagraph(b.sel) {
				flushEntry()
				entry.Component = normText(b.sel)
				return nil
			}
			if t := normText(b.sel); t != "" {
				entry.classify(t)
			}
		case "note":
			if t := normText(b.sel); t != "" {
				entry.Notes = append(entry.Notes, t)
			}
		case "ul":
			for _, li := range b.sel.ChildrenFiltered("li").EachIter() {
				lbs := blocks(li)
				if len(lbs) == 0 {
					if t := normText(li); t != "" {
						entry.classify(t)
					}
					continue
				}
				for _, lb := range lbs {
					if err := handle(lb); err != nil {
						return err
					}
				}
			}
		case "table":
			return errors.New("unexpected table in advisory page")
		default:
		}
		return nil
	}
	for _, b := range blocks(s) {
		if err := handle(b); err != nil {
			return Advisory{}, err
		}
	}
	flushSection()

	// advisory.Title may be empty: pages are sometimes served with an empty
	// <h1> for hours at a time; the name is recoverable from the release
	// list, so only missing sections are treated as a format change
	if len(advisory.Sections) == 0 {
		return Advisory{}, errors.New("no sections found in advisory page")
	}

	return advisory, nil
}

func (e Entry) isEmpty() bool {
	return e.Component == "" && len(e.AvailableFor) == 0 && len(e.Impact) == 0 && len(e.Description) == 0 && len(e.IDs) == 0 && len(e.Notes) == 0 && len(e.Others) == 0
}

// classify sorts a paragraph into the matching entry field by its label.
func (e *Entry) classify(t string) {
	switch {
	case strings.HasPrefix(t, "Available for:"):
		e.AvailableFor = append(e.AvailableFor, strings.TrimSpace(strings.TrimPrefix(t, "Available for:")))
	case strings.HasPrefix(t, "Impact:"):
		e.Impact = append(e.Impact, strings.TrimSpace(strings.TrimPrefix(t, "Impact:")))
	case strings.HasPrefix(t, "Description:"):
		e.Description = append(e.Description, strings.TrimSpace(strings.TrimPrefix(t, "Description:")))
	case strings.HasPrefix(t, "CVE-"), strings.HasPrefix(t, "CAN-"), strings.HasPrefix(t, "CVE ID:"), strings.HasPrefix(t, "CVE IDs:"), strings.HasPrefix(t, "WebKit Bugzilla"):
		e.IDs = append(e.IDs, t)
	default:
		e.Others = append(e.Others, t)
	}
}
