// Package servicing fetches Microsoft's servicing articles — the per-update
// pages under support.microsoft.com/<locale>/servicing/.
//
// These pages are the only durable record of which updates belong to a
// servicing series. The Update Catalog drops an update outright once Microsoft
// expires it: search returns nothing, ScopedViewInline redirects to
// Thanks.aspx, and the "This update replaces the following updates" list on the
// surviving successor is rewritten to "n/a". wsusscn2.cab drops it too. The
// servicing article, by contrast, stays served, and every article in a series
// carries a sidebar listing the whole series — expired updates included.
//
// That matters for supersedence. KB5033920 (2024-01, .NET for Windows 11 23H2)
// fixes CVE-2024-0057, and a host patched to KB5101004 (2026-07) is covered by
// the chain 5101004 -> 5049624 -> 5044033 -> 5039895 -> 5036620 -> 5033920.
// Four of those five links are expired, so the chain cannot be walked from the
// catalog at all; the sidebar on any article in the series still lists all six
// in order.
//
// Fetching is two steps. The articles asked for are stored and their sidebars
// read; then everything those sidebars name is stored, without reading its
// sidebar in turn. One hop is enough — a sidebar repeated on every article of a
// series has nothing more to say — and it is also the limit worth taking: a
// Windows Server 2008 sidebar links into Windows 8.1, so following further
// would pull in a series nobody asked for.
//
// fetch writes <dir>/origin verbatim and then produces <dir>/raw by reading it
// back, never the HTTP response, so raw/ is reproducible from origin/ alone.
// Only the heading and the canonical link are read out; the prose sections stay
// in origin/ for a later pass.
package servicing

import (
	"context"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

// helpURL resolves a KB number to its servicing article. support.microsoft.com
// redirects /help/<KB> to the canonical path, which is also how the product and
// series are discovered: they are path segments, not page content.
const helpURL = "https://support.microsoft.com/help/%s"

var (
	// servicingPathPattern splits a canonical path into locale, product and the
	// remainder. Depth varies — os/windows-11, dotnetframework/windows-11/22h2
	// and azure/stack-hci/update are all series — so the series cannot be taken
	// as a fixed number of segments.
	servicingPathPattern = regexp.MustCompile(`^/([a-zA-Z-]+)/servicing/([^/]+)/(.+)$`)

	// datePattern is the year/month pair Microsoft inserts before the slug. It
	// is the only reliable series boundary, but not every article has one:
	// /servicing/dotnetframework/windows-11/3-5/<slug> has none.
	datePattern = regexp.MustCompile(`^(\d{4})/(\d{2})/`)

	// sidebarPattern matches one series-listing item, capturing the class so
	// headings can be told from articles, and the href, which is absent on the
	// item for the article being viewed.
	sidebarPattern = regexp.MustCompile(`(?s)<li class="(learnRenderLeftNav[^"]*)"[^>]*>\s*(?:<a href="([^"]*)"[^>]*>)?(.*?)</li>`)

	headingPattern = regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`)

	// canonicalPattern reads the article's own address off the page, so raw/
	// records where it came from without that having to be remembered from the
	// request that fetched it.
	canonicalPattern = regexp.MustCompile(`<link[^>]*\brel="canonical"[^>]*\bhref="([^"]*)"`)

	tagPattern   = regexp.MustCompile(`<[^>]*>`)
	spacePattern = regexp.MustCompile(`\s+`)

	// flightingPattern strips the analytics metadata support.microsoft.com
	// varies per response. awa-userFlightingId is a fresh GUID every time and
	// awa-expid is an A/B bucket assignment; leaving them in makes every article
	// differ on every fetch, which is exactly the churn origin/ exists to avoid.
	// Removing them makes the served bytes reproduce exactly.
	flightingPattern = regexp.MustCompile(`\s*<meta name="awa-[^"]*"[^>]*/?>`)
)

type options struct {
	helpURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
}

type Option interface {
	apply(*options)
}

type helpURLOption string

func (u helpURLOption) apply(opts *options) {
	opts.helpURL = string(u)
}

func WithHelpURL(url string) Option {
	return helpURLOption(url)
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

// retryPolicy adds 403 to what the client already retries on.
//
// support.microsoft.com answers 403, not 429, when it decides a client is
// asking too often, and a crawl over a few thousand articles reaches that in
// minutes. The default policy covers 429 and 5xx, so without this the first
// throttle ends the run. A 403 that is not throttling costs the same bounded
// number of attempts before failing exactly as it would have.
func retryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	retry, rerr := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err)
	if retry || rerr != nil {
		return retry, rerr
	}

	return resp != nil && resp.StatusCode == http.StatusForbidden, nil
}

// errNotServed reports an article support.microsoft.com does not serve. A
// listing naming one is Microsoft's own inconsistency, not a fetch failure, so
// the crawl steps over it rather than losing the run.
var errNotServed = errors.New("not served")

// entry is one item of a series listing. It is a crawl frontier, not data: the
// listing is only read to find the rest of the series, and the articles it
// points at are stored in its place.
type entry struct {
	title string
	href  string
}

// article is one resolved KB: where support.microsoft.com serves it and which
// series it belongs to.
type article struct {
	url string // where support.microsoft.com served it, after redirects

	product string
	line    []string
	rest    string // path below the series, e.g. 2025/10/october-14-2025-...
}

// stem is the article's path inside the tree, without an extension, mirroring
// the canonical URL so origin/ and raw/ stay navigable against the site they
// came from.
func (a article) stem() string {
	return path.Join(slices.Concat([]string{a.product}, a.line, []string{a.rest})...)
}

// name is where the article is stored under origin/.
func (a article) name() string {
	return fmt.Sprintf("%s.html", a.stem())
}

// Fetch stores servicing articles under <dir>/origin and the series listings
// they carry under <dir>/raw.
//
// The whole series is stored, not only the articles asked for. One article is
// retrieved per series to read its listing, and every article the listing names
// is then retrieved as well. The listing alone would be cheaper, but it is a
// single point of failure: Microsoft has already rewritten the Update Catalog's
// "This update replaces the following updates" to "n/a" on updates that
// demonstrably replaced something, and a listing pruned the same way would take
// every expired member with it. Each article is its own record.
//
// Series that render no listing — os/windows and os/windows-server collect
// unrelated one-off notices rather than a monthly track — are the exception,
// and every KB landing on one is retrieved.
func Fetch(kbs []string, opts ...Option) error {
	options := &options{
		helpURL:     helpURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "microsoft", "servicing"),
		retry:       3,
		concurrency: 3,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if len(kbs) == 0 {
		return errors.New("no KB specified")
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	if err := options.fetch(kbs); err != nil {
		return errors.Wrap(err, "fetch")
	}

	if err := options.convert(); err != nil {
		return errors.Wrap(err, "convert")
	}

	return nil
}

func (opts options) fetch(kbs []string) error {
	slog.Info("Fetch Microsoft Servicing Articles")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry), utilhttp.WithClientCheckRetry(retryPolicy))

	seeds, err := opts.resolve(client, util.Unique(kbs))
	if err != nil {
		return errors.Wrap(err, "resolve")
	}

	stored := make(map[string]struct{}, len(seeds))
	targets, err := opts.discover(client, seeds, stored)
	if err != nil {
		return errors.Wrap(err, "discover")
	}

	if err := opts.collect(client, targets, stored); err != nil {
		return errors.Wrap(err, "collect")
	}

	return nil
}

// resolve maps each KB to the article support.microsoft.com serves for it.
//
// HEAD is enough: only the redirect target is wanted, and it carries the
// product and series as path segments, so the body would add nothing a crawl
// does not already reach.
func (opts options) resolve(client *utilhttp.Client, kbs []string) ([]article, error) {
	slog.Info("Resolve KB to servicing article", slog.Int("count", len(kbs)))

	bar := progressbar.Default(int64(len(kbs)))
	articleChan := make(chan article, len(kbs))
	var g errgroup.Group
	g.SetLimit(opts.concurrency)
	for _, kb := range kbs {
		g.Go(func() error {
			defer func() {
				time.Sleep(opts.wait)
				_ = bar.Add(1)
			}()

			// /help/ takes the article number alone; /help/KB5101004 is a 404.
			// Callers pass either spelling, so normalize rather than reject, and
			// keep the normalized form: it is what sidebar entries carry, and the
			// two have to compare equal for a series to cover its members.
			kb = strings.TrimPrefix(strings.ToUpper(kb), "KB")

			req, err := utilhttp.NewRequest(http.MethodHead, fmt.Sprintf(opts.helpURL, kb))
			if err != nil {
				return errors.Wrapf(err, "new request for %s", kb)
			}

			resp, err := client.Do(req)
			if err != nil {
				return errors.Wrapf(err, "head %s", kb)
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != http.StatusOK {
				slog.Warn("unexpected status", slog.String("kb", kb), slog.Int("status", resp.StatusCode))
				return nil
			}

			a, ok := parsePath(resp.Request.URL)
			if !ok {
				// Pre-2018 KBs and hub pages stay on /help/<KB> or land on a
				// product landing page. There is no series to read there.
				slog.Warn("not a servicing article", slog.String("kb", kb), slog.String("url", resp.Request.URL.String()))
				return nil
			}
			a.url = resp.Request.URL.String()

			articleChan <- a

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, errors.Wrap(err, "err in goroutine")
	}
	close(articleChan)
	_ = bar.Close()

	articles := make([]article, 0, len(kbs))
	for a := range articleChan {
		articles = append(articles, a)
	}

	// Ordered so a rerun walks the same tree in the same order rather than in
	// whatever order the lookups happened to finish.
	slices.SortFunc(articles, func(a, b article) int { return strings.Compare(a.name(), b.name()) })

	return articles, nil
}

// discover stores the articles asked for and reports what their listings name.
//
// Only these listings are read. Following them further would not find anything
// in the same series -- the listing is identical on every article of one -- but
// it would leave the series entirely: a Windows Server 2008 listing links to
// os/windows-8-1/2024/01/end-of-support, and reading that article's listing in
// turn would drag in the whole of Windows 8.1. One hop keeps a request for a
// series to that series and whatever it points at directly.
func (opts options) discover(client *utilhttp.Client, seeds []article, stored map[string]struct{}) ([]article, error) {
	slog.Info("Discover series", slog.Int("articles", len(seeds)))

	bar := progressbar.Default(int64(len(seeds)))
	targetChan := make(chan []article, len(seeds))
	var g errgroup.Group
	g.SetLimit(opts.concurrency)
	for _, a := range seeds {
		if _, ok := stored[a.name()]; ok {
			_ = bar.Add(1)
			continue
		}
		stored[a.name()] = struct{}{}

		g.Go(func() error {
			defer func() {
				time.Sleep(opts.wait)
				_ = bar.Add(1)
			}()

			bs, err := opts.store(client, a)
			if err != nil {
				if errors.Is(err, errNotServed) {
					slog.Warn("article is not served", slog.String("url", a.url))
					return nil
				}
				return errors.Wrapf(err, "store %s", a.url)
			}

			var targets []article
			for _, e := range parseSidebar(string(bs)) {
				if e.href == "" {
					continue
				}
				b, ok := resolveHref(a, e.href)
				if !ok {
					slog.Warn("unexpected listing target", slog.String("href", e.href), slog.String("from", a.url))
					continue
				}
				targets = append(targets, b)
			}

			targetChan <- targets

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, errors.Wrap(err, "err in goroutine")
	}
	close(targetChan)
	_ = bar.Close()

	var targets []article
	for t := range targetChan {
		targets = append(targets, t...)
	}
	slices.SortFunc(targets, func(a, b article) int { return strings.Compare(a.name(), b.name()) })

	return targets, nil
}

// collect stores the rest of the series. Their listings are not read: they say
// what discover has already been told.
func (opts options) collect(client *utilhttp.Client, targets []article, stored map[string]struct{}) error {
	targets = slices.DeleteFunc(targets, func(a article) bool {
		if _, ok := stored[a.name()]; ok {
			return true
		}
		stored[a.name()] = struct{}{}
		return false
	})

	slog.Info("Collect series", slog.Int("articles", len(targets)))

	bar := progressbar.Default(int64(len(targets)))
	var g errgroup.Group
	g.SetLimit(opts.concurrency)
	for _, a := range targets {
		g.Go(func() error {
			defer func() {
				time.Sleep(opts.wait)
				_ = bar.Add(1)
			}()

			if _, err := opts.store(client, a); err != nil {
				if errors.Is(err, errNotServed) {
					slog.Warn("listed article is not served", slog.String("url", a.url))
					return nil
				}
				return errors.Wrapf(err, "store %s", a.url)
			}

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	_ = bar.Close()

	return nil
}

// store retrieves one article, writes it to origin/ and reports the KBs its
// sidebar accounts for.
func (opts options) store(client *utilhttp.Client, a article) ([]byte, error) {
	// The URL the redirect landed on is used as-is rather than rebuilt from the
	// parsed segments: rebuilding would silently diverge the moment Microsoft
	// changes a locale prefix or adds a path level.
	resp, err := client.Get(a.url)
	if err != nil {
		return nil, errors.Wrapf(err, "get %s", a.url)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Wrapf(errNotServed, "get %s", a.url)
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d, url: %s", resp.StatusCode, a.url)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", a.url)
	}

	bs = flightingPattern.ReplaceAll(bs, nil)

	if err := writeOrigin(opts.dir, a.name(), bs); err != nil {
		return nil, errors.Wrapf(err, "write %s", a.name())
	}

	return bs, nil
}

// convert reads origin/ back and writes raw/, one file per stored article so
// that which JSON came from which HTML is a matter of the path. Going through
// the stored bytes rather than the response is what lets the tree be re-derived
// after this parser changes.
func (opts options) convert() error {
	slog.Info("Convert origin to raw")

	root := filepath.Join(opts.dir, "origin")
	if _, err := os.Stat(root); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return errors.Wrapf(err, "stat %s", root)
		}
		// Every KB resolved to something outside /servicing/. There is nothing
		// to convert, and that is not a failure of the run.
		slog.Warn("no servicing article stored", slog.String("dir", root))
		return nil
	}

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

		bs, err := os.ReadFile(p)
		if err != nil {
			return errors.Wrapf(err, "read %s", p)
		}

		a, ok := parseArticle(string(bs))
		if !ok {
			// A page with no heading is not an article. It is stored either way,
			// so nothing is lost by having no JSON beside it.
			slog.Warn("no heading", slog.String("path", filepath.ToSlash(rel)))
			return nil
		}

		n := fmt.Sprintf("%s.json", strings.TrimSuffix(filepath.ToSlash(rel), ".html"))
		if err := util.Write(filepath.Join(opts.dir, "raw", filepath.FromSlash(n)), a); err != nil {
			return errors.Wrapf(err, "write %s", n)
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	return nil
}

// writeOrigin stores content under <dir>/origin/<name> as served.
//
// Nothing derived from the response is recorded alongside it — no fetch
// timestamp, no ETag, no status line. Those change on every run even when the
// article does not, and would turn every fetch into a diff, drowning the signal
// this tree exists to carry: that Microsoft revised the article.
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

// resolveHref turns a listing href, which is relative to the article it was
// read from, into the article it points at.
func resolveHref(from article, href string) (article, bool) {
	base, err := url.Parse(from.url)
	if err != nil {
		return article{}, false
	}

	ref, err := url.Parse(href)
	if err != nil {
		return article{}, false
	}

	target := base.ResolveReference(ref)

	a, ok := parsePath(target)
	if !ok {
		return article{}, false
	}
	a.url = target.String()

	return a, true
}

// parsePath splits a canonical servicing URL into its product, series and the
// path below it.
func parsePath(u *url.URL) (article, bool) {
	// A canonical servicing path has no dot-segments, and url.ResolveReference,
	// which every URL reaching here has been through, removes the ones a redirect
	// or an href spells out. It removes them from the escaped path, though, while
	// Path is decoded: %2e%2e survives resolution and arrives here as "..", from
	// where filepath.Join would carry the write out of origin/. Reject rather
	// than clean — no article is addressed that way, so nothing is lost.
	//
	// This is the only place an article is built, and its name is the only path
	// origin/ is written at, so the check covers both the redirect resolve reads
	// and the listing hrefs resolveHref follows.
	for s := range strings.SplitSeq(u.Path, "/") {
		if s == "." || s == ".." {
			return article{}, false
		}
	}

	m := servicingPathPattern.FindStringSubmatch(u.Path)
	if m == nil {
		return article{}, false
	}

	// support.microsoft.com serves the same page under DotNetFramework and
	// dotnetframework; without folding the case the two spellings become two
	// series holding the same articles.
	product := strings.ToLower(m[2])
	rest := m[3]

	// Everything up to the year/month is the series. Articles without one keep
	// the last segment as the slug, which is the shape
	// dotnetframework/windows-11/3-5/<slug> takes.
	var line []string
	segs := strings.Split(rest, "/")
	for i := range segs {
		if datePattern.MatchString(strings.Join(segs[i:], "/")) {
			return article{product: product, line: line, rest: strings.Join(segs[i:], "/")}, true
		}
		if i == len(segs)-1 {
			break
		}
		line = append(line, strings.ToLower(segs[i]))
	}

	return article{product: product, line: line, rest: segs[len(segs)-1]}, true
}

// parseSidebar reads the series listing rendered beside every article.
//
// The same list carries section headings ("Windows 11, version 26H1", "End of
// servicing statement"), which are not articles. They are told apart by the
// class Microsoft marks them with rather than by their text, so a heading that
// happens to look like an entry is still excluded.
func parseSidebar(doc string) []entry {
	var es []entry
	for _, m := range sidebarPattern.FindAllStringSubmatch(doc, -1) {
		if !strings.Contains(m[1], "learnRenderLeftNavArticle") {
			continue
		}

		title := text(m[3])
		if title == "" {
			continue
		}

		es = append(es, entry{title: title, href: m[2]})
	}

	return es
}

// parseArticle reads what an article states about itself.
func parseArticle(doc string) (Article, bool) {
	m := headingPattern.FindStringSubmatch(doc)
	if m == nil {
		return Article{}, false
	}

	title := text(m[1])
	if title == "" {
		return Article{}, false
	}

	a := Article{Title: title}
	if cm := canonicalPattern.FindStringSubmatch(doc); cm != nil {
		a.URL = text(cm[1])
	}

	return a, true
}

func text(s string) string {
	return strings.TrimSpace(spacePattern.ReplaceAllString(html.UnescapeString(tagPattern.ReplaceAllString(s, "")), " "))
}
