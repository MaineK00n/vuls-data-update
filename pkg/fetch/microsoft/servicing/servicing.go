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
// Fetching is two steps, one reading and one writing. The sidebar on each
// article asked for is read to learn the rest of its series; then every article
// they name — the ones asked for included — is retrieved and stored, and no
// further sidebar is read. One hop is enough — a sidebar repeated on every
// article of a series has nothing more to say — and it is also the limit worth
// taking: a Windows Server 2008 sidebar links into Windows 8.1, so following
// further would pull in a series nobody asked for.
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
		return retry, errors.Wrap(rerr, "retry policy")
	}

	// The status goes with the decision: given a nil error, retryablehttp gives
	// up saying only "giving up after N attempt(s)", never that it was throttled.
	if resp != nil && resp.StatusCode == http.StatusForbidden {
		return true, errors.Errorf("unexpected HTTP status %s", resp.Status)
	}

	return false, nil
}

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
// The defaults are set by what support.microsoft.com throttles at, measured
// over 200 articles per run:
//
//	concurrency  retry   403s   backoff   gave up
//	          3      3     77      140s        12
//	          3      5     42      114s         1
//	          3      8     23       57s         0
//	          1      5      8       10s         0
//	          2      5      9       12s         0
//
// Waiting longer between requests is not the lever: at one request a second the
// throttle arrives after 46 articles, at two a second after 75. It is a quota
// over a window, and any crawl worth running reaches it.
//
// What matters is going quiet once it does. The window is 3 to 5 seconds when
// nothing is asking, so a lone worker's first retry clears it -- but a third
// worker keeps the quota spent while the other two back off, and their retries
// then land together and spend it again. Hence two, which throttles a fifth as
// often as three for the same throughput.
//
// retry is well past the 5 that measured clean, because an unused retry costs
// nothing and a real seed list is many times 200 articles. nvd/api, against an
// API that throttles the same way, allows 20.
func Fetch(kbs []string, opts ...Option) error {
	options := &options{
		helpURL:     helpURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "microsoft", "servicing"),
		retry:       10,
		concurrency: 2,
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

	seeds, err := opts.resolve(client, kbs)
	if err != nil {
		return errors.Wrap(err, "resolve")
	}

	targets, err := opts.discover(client, seeds)
	if err != nil {
		return errors.Wrap(err, "discover")
	}

	if err := opts.collect(client, targets); err != nil {
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
	// /help/ takes the article number alone; /help/KB5101004 is a 404. Callers
	// pass either spelling, so normalize rather than reject — and normalize
	// before deduplicating, or "KB5101004" and "5101004" are two lookups of the
	// one article.
	ns := make([]string, 0, len(kbs))
	for _, kb := range kbs {
		ns = append(ns, strings.TrimPrefix(strings.ToUpper(kb), "KB"))
	}
	kbs = util.Unique(ns)

	slog.Info("Resolve KB to servicing article", slog.Int("count", len(kbs)))

	reqs := make([]*retryablehttp.Request, 0, len(kbs))
	for _, kb := range kbs {
		req, err := utilhttp.NewRequest(http.MethodHead, fmt.Sprintf(opts.helpURL, kb))
		if err != nil {
			return nil, errors.Wrapf(err, "new request for %s", kb)
		}
		reqs = append(reqs, req)
	}

	articleChan := make(chan article, len(kbs))
	if err := client.PipelineDo(reqs, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode != http.StatusOK {
			slog.Warn("unexpected status", slog.String("url", resp.Request.URL.String()), slog.Int("status", resp.StatusCode))
			return nil
		}

		a, ok := parsePath(resp.Request.URL)
		if !ok {
			// Pre-2018 KBs and hub pages stay on /help/<KB> or land on a product
			// landing page. There is no series to read there.
			slog.Warn("not a servicing article", slog.String("url", resp.Request.URL.String()))
			return nil
		}
		a.url = resp.Request.URL.String()

		articleChan <- a

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline do")
	}
	close(articleChan)

	articles := make([]article, 0, len(kbs))
	for a := range articleChan {
		articles = append(articles, a)
	}

	return articles, nil
}

// discover reads the listing on each article asked for and reports every
// article to store: the ones asked for, and the rest of the series each names.
//
// Nothing is written here. Reading a listing means retrieving the article
// carrying it, and keeping those bytes would make this the second place that
// writes origin/ -- one that writes some articles while collect writes the
// others. Retrieving them again there costs one request per KB asked for and
// leaves one function answering for the tree.
//
// Only these listings are read. Following them further would not find anything
// in the same series -- the listing is identical on every article of one -- but
// it would leave the series entirely: a Windows Server 2008 listing links to
// os/windows-8-1/2024/01/end-of-support, and reading that article's listing in
// turn would drag in the whole of Windows 8.1. One hop keeps a request for a
// series to that series and whatever it points at directly.
func (opts options) discover(client *utilhttp.Client, seeds []article) ([]article, error) {
	slog.Info("Discover series", slog.Int("articles", len(seeds)))

	us := make([]string, 0, len(seeds))
	for _, a := range seeds {
		// The URL the redirect landed on is used as-is rather than rebuilt from
		// the parsed segments: rebuilding would silently diverge the moment
		// Microsoft changes a locale prefix or adds a path level.
		us = append(us, a.url)
	}

	articleChan := make(chan []article, len(seeds))
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

		// The seed is reported alongside what its listing names, since a series
		// of one -- or one rendering no listing at all, as os/windows does --
		// would otherwise be discovered by nothing.
		a, ok := parsePath(resp.Request.URL)
		if !ok {
			return errors.Errorf("unexpected url. expected: %q, actual: %q", "/<locale>/servicing/<product>/.../<article>", resp.Request.URL)
		}
		a.url = resp.Request.URL.String()
		articles := []article{a}

		for _, e := range parseSidebar(string(bs)) {
			if e.href == "" {
				continue
			}
			b, ok := resolveHref(resp.Request.URL, e.href)
			if !ok {
				slog.Warn("unexpected listing target", slog.String("href", e.href), slog.String("from", resp.Request.URL.String()))
				continue
			}
			articles = append(articles, b)
		}

		articleChan <- articles

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline get")
	}
	close(articleChan)

	// A listing names its whole series and one was read per KB asked for, so
	// three members of os/windows-11 name its 300 articles 900 times between
	// them. Each is one article and is stored once.
	seen := make(map[string]struct{}, len(seeds))
	var articles []article
	for as := range articleChan {
		for _, a := range as {
			if _, ok := seen[a.name()]; ok {
				continue
			}
			seen[a.name()] = struct{}{}
			articles = append(articles, a)
		}
	}

	return articles, nil
}

// collect stores every article discover reported. Their listings are not read:
// they say what discover has already been told.
func (opts options) collect(client *utilhttp.Client, articles []article) error {
	slog.Info("Collect articles", slog.Int("articles", len(articles)))

	us := make([]string, 0, len(articles))
	for _, a := range articles {
		us = append(us, a.url)
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

		// Taken from the response rather than carried in from the caller, so
		// where a page is stored follows the URL it was actually served at.
		a, ok := parsePath(resp.Request.URL)
		if !ok {
			return errors.Errorf("unexpected url. expected: %q, actual: %q", "/<locale>/servicing/<product>/.../<article>", resp.Request.URL)
		}

		if err := writeOrigin(opts.dir, a.name(), flightingPattern.ReplaceAll(bs, nil)); err != nil {
			return errors.Wrapf(err, "write %s", a.name())
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
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

		// Every servicing article carries its title in an h1 -- 20 of 20 sampled
		// across os/windows-11, os/server-2008, dotnetframework and the one-off
		// notices under os/windows, down to "End of support". A stored page
		// without one therefore means either that it is not an article, and
		// collect wrote something parsePath should not have accepted, or that
		// this heading is no longer where the title lives. Both apply to every
		// page at once, so skipping would leave raw/ empty beside a full origin/
		// with the run green.
		a, ok := parseArticle(string(bs))
		if !ok {
			return errors.Errorf("no heading in %s", p)
		}

		if err := util.Write(filepath.Join(opts.dir, "raw", fmt.Sprintf("%s.json", strings.TrimSuffix(rel, ".html"))), a); err != nil {
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
func resolveHref(base *url.URL, href string) (article, bool) {
	ref, err := url.Parse(href)
	if err != nil {
		return article{}, false
	}

	target := base.ResolveReference(ref)

	// A listing is HTML off the network, and an href in it that names a scheme
	// or a host rebases the target onto that host -- parsePath reads the path
	// alone, so anything serving /<locale>/servicing/... would be retrieved and
	// stored as a Microsoft servicing article. Nothing is lost by refusing:
	// every one of the 70,922 listing hrefs across 271 articles is relative.
	if target.Scheme != base.Scheme || target.Host != base.Host {
		return article{}, false
	}

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
