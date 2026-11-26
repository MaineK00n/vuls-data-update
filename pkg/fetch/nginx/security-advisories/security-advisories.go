package securityadvisories

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://nginx.org/en/security_advisories.html"

const (
	severityLabel      = "Severity:"
	notVulnerableLabel = "Not vulnerable:"
	vulnerableLabel    = "Vulnerable:"
)

// A patch line is recognised by either its anchor text or its download path,
// and parsePatch then requires both to hold. Accepting either keeps a rename of
// one of them from silently demoting a patch line to a reference line, and
// requiring both makes that rename surface as an error.
const (
	patchLinkText          = "The patch"
	patchSignatureLinkText = "pgp"
	patchPathPrefix        = "/download/patch"
)

// The ID is taken from the remote page and is used as a path element, so accept
// only the formats the page is known to use. Every entry links a CVE record
// except the 8.3 filename pseudonyms one, which predates its CVE assignment and
// carries a Core Security ID instead.
var advisoryIDPattern = regexp.MustCompile(`^(?:CVE|CORE)-([0-9]{4})-[0-9]{4,}$`)

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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
		dir:     filepath.Join(util.CacheDir(), "fetch", "nginx", "security-advisories"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch nginx Security Advisories")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch nginx security advisories")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	// Relative links (the patch downloads) are resolved against the canonical
	// page URL instead of the fetched one, so that the stored URLs keep
	// pointing at nginx.org when the page is read from a mirror or a test
	// server.
	base, err := url.Parse(dataURL)
	if err != nil {
		return errors.Wrapf(err, "parse %s", dataURL)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "parse as html")
	}

	// The advisories are the only list in the content area. Pinning the count
	// makes a page restructure fail here rather than silently yield nothing.
	uls := d.Find("#content > ul")
	if uls.Length() != 1 {
		return errors.Errorf("unexpected number of advisory lists. expected: %d, actual: %d", 1, uls.Length())
	}

	lis := uls.Find("li")
	if lis.Length() == 0 {
		return errors.Errorf("no advisory found in %s", options.dataURL)
	}

	for _, li := range lis.EachIter() {
		a, year, err := parseAdvisory(base, li)
		if err != nil {
			h, herr := goquery.OuterHtml(li)
			if herr != nil {
				return errors.Wrap(err, "parse advisory")
			}
			return errors.Wrapf(err, "parse advisory. html: %q", h)
		}

		if err := util.Write(filepath.Join(options.dir, year, fmt.Sprintf("%s.json", a.ID)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, year, fmt.Sprintf("%s.json", a.ID)))
		}
	}

	return nil
}

// link is an anchor of an advisory line, keeping the parsed URL so that a patch
// line can be told apart from a reference line without re-parsing.
type link struct {
	text string
	u    *url.URL
}

// line is one <br> separated line of an advisory entry. text holds the text
// outside the anchors only, which is what carries the labels and the patch
// applicability remark.
type line struct {
	text  string
	links []link
}

// parseAdvisory converts one <li> of the advisories list. It returns the
// advisory and the year its ID was issued for, which is the output directory.
func parseAdvisory(base *url.URL, li *goquery.Selection) (Advisory, string, error) {
	ps := li.ChildrenFiltered("p")
	if ps.Length() != 1 {
		return Advisory{}, "", errors.Errorf("unexpected number of paragraphs in an advisory. expected: %d, actual: %d", 1, ps.Length())
	}

	lines, err := splitLines(base, ps.Contents())
	if err != nil {
		return Advisory{}, "", errors.Wrap(err, "split lines")
	}

	// The title is the only line carrying bare text and no label.
	title := strings.TrimSpace(lines[0].text)
	if title == "" || len(lines[0].links) > 0 {
		return Advisory{}, "", errors.Errorf("unexpected first line. expected: %q, actual: %q", "a title without links", lines[0].text)
	}

	a := Advisory{Title: title}
	for _, l := range lines[1:] {
		t := strings.TrimSpace(l.text)

		switch {
		case strings.HasPrefix(t, severityLabel):
			if a.Severity != "" {
				return Advisory{}, "", errors.Errorf("duplicate %q line", severityLabel)
			}
			a.Severity = strings.TrimSpace(strings.TrimPrefix(t, severityLabel))
		case strings.HasPrefix(t, notVulnerableLabel):
			if len(a.NotVulnerable) > 0 {
				return Advisory{}, "", errors.Errorf("duplicate %q line", notVulnerableLabel)
			}
			a.NotVulnerable = splitVersions(strings.TrimPrefix(t, notVulnerableLabel))
		case strings.HasPrefix(t, vulnerableLabel):
			if len(a.Vulnerable) > 0 {
				return Advisory{}, "", errors.Errorf("duplicate %q line", vulnerableLabel)
			}
			a.Vulnerable = splitVersions(strings.TrimPrefix(t, vulnerableLabel))
		case len(l.links) > 0 && isPatchLink(l.links[0]):
			p, err := parsePatch(l)
			if err != nil {
				return Advisory{}, "", errors.Wrap(err, "parse patch line")
			}
			a.Patches = append(a.Patches, p)
		case len(l.links) > 0 && t == "":
			for _, lnk := range l.links {
				a.References = append(a.References, Reference{Text: lnk.text, URL: lnk.u.String()})
			}
		default:
			return Advisory{}, "", errors.Errorf("unexpected line. expected: %q, actual: %q", []string{severityLabel, notVulnerableLabel, vulnerableLabel, "a reference or patch line"}, t)
		}
	}

	switch {
	case a.Severity == "":
		return Advisory{}, "", errors.Errorf("no %q line", severityLabel)
	case len(a.NotVulnerable) == 0:
		return Advisory{}, "", errors.Errorf("no %q line", notVulnerableLabel)
	case len(a.Vulnerable) == 0:
		return Advisory{}, "", errors.Errorf("no %q line", vulnerableLabel)
	}

	id, year, err := advisoryID(a.References)
	if err != nil {
		return Advisory{}, "", errors.Wrap(err, "advisory id")
	}
	a.ID = id

	return a, year, nil
}

// splitLines groups the children of an advisory paragraph into <br> separated
// lines. Anchor text is kept out of line.text so that a label, or the remark
// trailing a patch link, can be read without stripping the link captions.
func splitLines(base *url.URL, contents *goquery.Selection) ([]line, error) {
	lines := make([]line, 0, contents.Length())
	var cur line

	for _, n := range contents.EachIter() {
		switch goquery.NodeName(n) {
		case "br":
			lines = append(lines, cur)
			cur = line{}
		case "a":
			href, ok := n.Attr("href")
			if !ok {
				return nil, errors.Errorf("no href on the %q anchor", n.Text())
			}
			ref, err := url.Parse(href)
			if err != nil {
				return nil, errors.Wrapf(err, "parse %s", href)
			}
			cur.links = append(cur.links, link{text: strings.TrimSpace(n.Text()), u: base.ResolveReference(ref)})
		default:
			// Only <b> around a "major" severity is expected to wrap text.
			// An anchor nested somewhere else means the markup changed in a
			// way the flat line model no longer describes.
			if n.Find("a").Length() > 0 {
				return nil, errors.Errorf("unexpected nested anchor in a %q element", goquery.NodeName(n))
			}
			cur.text += n.Text()
		}
	}

	return append(lines, cur), nil
}

func isPatchLink(l link) bool {
	return l.text == patchLinkText || strings.HasPrefix(l.u.Path, patchPathPrefix)
}

func parsePatch(l line) (Patch, error) {
	if len(l.links) > 2 {
		return Patch{}, errors.Errorf("unexpected number of links in a patch line. expected: %q, actual: %d", "1 or 2", len(l.links))
	}

	if l.links[0].text != patchLinkText {
		return Patch{}, errors.Errorf("unexpected patch link text. expected: %q, actual: %q", patchLinkText, l.links[0].text)
	}
	if !strings.HasPrefix(l.links[0].u.Path, patchPathPrefix) {
		return Patch{}, errors.Errorf("unexpected patch link path. expected: %q, actual: %q", patchPathPrefix, l.links[0].u.Path)
	}

	p := Patch{
		URL:  l.links[0].u.String(),
		Note: strings.TrimSpace(l.text),
	}

	if len(l.links) == 2 {
		if l.links[1].text != patchSignatureLinkText {
			return Patch{}, errors.Errorf("unexpected patch signature link text. expected: %q, actual: %q", patchSignatureLinkText, l.links[1].text)
		}
		p.SignatureURL = l.links[1].u.String()
	}

	return p, nil
}

// advisoryID picks the reference that identifies the advisory and returns it
// with its year. More than one candidate is an error rather than a silent
// choice, so that an entry covering several IDs surfaces instead of being
// filed under an arbitrary one.
func advisoryID(refs []Reference) (string, string, error) {
	var (
		id   string
		year string
	)
	for _, r := range refs {
		m := advisoryIDPattern.FindStringSubmatch(r.Text)
		if m == nil {
			continue
		}
		if id != "" {
			return "", "", errors.Errorf("multiple advisory ids. first: %q, second: %q", id, r.Text)
		}
		id, year = r.Text, m[1]
	}

	if id == "" {
		texts := make([]string, 0, len(refs))
		for _, r := range refs {
			texts = append(texts, r.Text)
		}
		return "", "", errors.Errorf("no advisory id found. expected: %q, actual: %q", advisoryIDPattern.String(), texts)
	}

	return id, year, nil
}

func splitVersions(s string) []string {
	vs := make([]string, 0, strings.Count(s, ",")+1)
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			vs = append(vs, v)
		}
	}
	return vs
}
