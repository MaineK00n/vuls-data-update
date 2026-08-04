package xml

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

// The Apache Tomcat website is built from these xdocs sources. The published
// security-<branch>.html pages carry the same content, but the source marks up
// the parts that matter — <cve> for an entry's own CVEs, the rtext attribute
// for the release date, <hashlink>/<revlink>/<bug> for fix references — where
// the rendered page leaves them to be recovered from link targets and CSS
// classes.
const baseURL = "https://svn.apache.org/repos/asf/tomcat/site/trunk/xdocs/"

// securityPagePattern matches the vulnerability listings, one per branch:
// security-{3..11}.xml plus the separately-versioned components
// security-{jk,native,taglibs}.xml. A new branch is picked up automatically.
var securityPagePattern = regexp.MustCompile(`^security-([0-9]+|[a-z]+)\.xml$`)

// nonVulnerabilityPages are the security-*.xml files under xdocs that document
// policy rather than vulnerabilities, so they carry no advisory sections.
var nonVulnerabilityPages = []string{"security-impact.xml", "security-model.xml"}

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "apache", "tomcat", "xml"),
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

	slog.Info("Fetch Apache Tomcat Security Vulnerabilities")
	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (opts options) fetch() error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	us, err := opts.fetchIndexOf(client)
	if err != nil {
		return errors.Wrap(err, "fetch index of")
	}
	if len(us) == 0 {
		return errors.Errorf("no %s found in %s", securityPagePattern.String(), opts.baseURL)
	}

	if err := client.PipelineGet(us, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d for %q", resp.StatusCode, path.Base(resp.Request.URL.Path))
		}

		b := path.Base(resp.Request.URL.Path)
		m := securityPagePattern.FindStringSubmatch(b)
		if m == nil {
			return errors.Errorf("unexpected file name. expected: %q, actual: %q", securityPagePattern.String(), b)
		}

		var doc document
		if err := xml.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return errors.Wrapf(err, "decode %s as xml", b)
		}

		a := parse(m[1], doc)
		if err := util.Write(filepath.Join(opts.dir, fmt.Sprintf("%s.json", a.Branch)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, fmt.Sprintf("%s.json", a.Branch)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

// fetchIndexOf collects the per-branch vulnerability listings linked from the
// xdocs directory index. security-*.xml files that document policy rather than
// vulnerabilities are skipped by name; anything else matching the pattern is
// treated as a branch listing, so a new branch (security-12.xml) is picked up
// without a code change.
func (opts options) fetchIndexOf(client *utilhttp.Client) ([]string, error) {
	resp, err := client.Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", opts.baseURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var us []string
	for _, s := range d.Find("a").EachIter() {
		href, ok := s.Attr("href")
		if !ok {
			continue
		}

		ref, err := url.Parse(href)
		if err != nil {
			return nil, errors.Wrapf(err, "parse %s", href)
		}
		u := resp.Request.URL.ResolveReference(ref)

		b := path.Base(u.Path)
		if slices.Contains(nonVulnerabilityPages, b) || !securityPagePattern.MatchString(b) {
			continue
		}
		if !slices.Contains(us, u.String()) {
			us = append(us, u.String())
		}
	}

	return us, nil
}

// parse attaches the branch to the decoded document. The page's own structure
// is preserved as decoded; grouping its paragraphs into vulnerabilities is the
// extractor's job.
func parse(branch string, doc document) Advisory {
	return Advisory{
		Branch:     branch,
		Properties: doc.Properties,
		Sections:   doc.Body.Sections,
	}
}
