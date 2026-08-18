// Package security stores OpenSSH's security page and the instructions for
// converting it.
//
// https://www.openssh.com/security.html is OpenSSH's entire security history
// and it is prose. Each entry is an <li> of English, dated at best, and the CVE
// ID, the affected versions and the release carrying the fix are stated in
// whatever wording that entry's author reached for — "versions 7.4 to 9.9
// (inclusive)", "prior to version 9.6", "9.1 (only)", "4.4 and newer is not
// vulnerable to". Roughly a quarter of the list exists to record that a
// vulnerability reported against SSH at large never applied to OpenSSH, and
// reads almost exactly like the entries that say it did.
//
// A parser for that would be a pile of per-entry special cases that breaks on
// the next entry written in a new voice, and breaks silently — a phrasing it
// does not recognize yields no versions rather than an error. So this fetcher
// does not parse. It stores the page under origin/ and stops.
//
// The conversion to raw/ is a separate, model-driven step, run by hand against
// the stored copy (see skill/SKILL.md, which Fetch writes into the output tree
// so the instructions travel with the data they describe). What makes that
// trustworthy rather than a black box is that each raw/ record carries the <li>
// it was read from: every field can be checked against its source without
// leaving the repository, and re-running the conversion against an unchanged
// origin/ must produce no diff.
//
// Which is also why origin/ holds more than the page: a raw/ record may cite a
// document, and it can only stay checkable on the terms above if the document
// is here too. An annotation quotes a sentence, and the sentence has to be in
// the repository.
//
// Two kinds are stored, for two different gaps. The release notes and
// advisories the page links, under origin/txt/, carry the fix releases and the
// detail the entries compress. The CVE records, under origin/mitre/, carry the
// IDs -- which the project's own documents almost never do, because OpenSSH is
// not a CNA and the IDs are assigned elsewhere. Measured over the whole page:
// six of the 55 entries name an ID, and of the other 49 exactly one has a
// linked release note that names any, which turns out on reading to be
// Solaris' rather than OpenSSH's.
//
// Hence what Fetch is careful about: it replaces origin/ and leaves everything
// else in the output directory alone. raw/ is the expensive part of this tree
// and is not the fetcher's to discard.
package security

import (
	"bytes"
	_ "embed"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	defaultURL = "https://www.openssh.com/security.html"

	// nvdURL enumerates which CVE IDs are about OpenSSH; cveURL is where each
	// record is then read from.
	//
	// The split is not a preference between the two. cve.org holds the record
	// as the assigning CNA wrote it -- for OpenSSH that is a third party, since
	// the project is not a CNA, and the CNA states the affected range in the
	// page's own terms ("8.5p1", lessThanOrEqual "9.7p1", versionType custom)
	// where NVD's CPE re-encoding cannot and loses the portable release. But
	// cve.org has no product index to ask "which CVEs are OpenSSH's", and NVD
	// does. So the list comes from one and the content from the other.
	defaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultCVEURL = "https://cveawg.mitre.org/api/cve"
)

// nvdResultsPerPageMax is the largest page the NVD API serves.
const nvdResultsPerPageMax = 2_000

// minEntries is the floor a stored page has to clear. The list holds 55 entries
// and only grows: entries are added at the top and none has ever been removed,
// so a body carrying fewer is not this page. The floor sits well under the
// current count so that an upstream reorganization of the list does not need it
// bumped, while still rejecting the error pages and portal interstitials that
// arrive with a 200.
const minEntries = 40

// skillPath is where the conversion instructions are written, relative to the
// output directory. The .claude/skills/<name>/SKILL.md layout is what makes an
// agent started in the raw repository discover them on its own, which is the
// point of shipping them here rather than leaving them in vuls-data-update: the
// conversion runs in the data repository, and the instructions that describe
// this fetcher's output should be the ones that shipped with it.
var skillPath = filepath.Join(".claude", "skills", "openssh-security-raw", "SKILL.md")

//go:embed skill/SKILL.md
var skill []byte

type options struct {
	url            string
	nvdURL         string
	cveURL         string
	dir            string
	retry          int
	concurrency    int
	wait           time.Duration
	resultsPerPage int
}

type Option interface {
	apply(*options)
}

type urlOption string

func (u urlOption) apply(opts *options) {
	opts.url = string(u)
}

func WithURL(url string) Option {
	return urlOption(url)
}

type nvdURLOption string

func (u nvdURLOption) apply(opts *options) {
	opts.nvdURL = string(u)
}

func WithNVDURL(url string) Option {
	return nvdURLOption(url)
}

type cveURLOption string

func (u cveURLOption) apply(opts *options) {
	opts.cveURL = string(u)
}

func WithCVEURL(url string) Option {
	return cveURLOption(url)
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

type resultsPerPageOption int

func (r resultsPerPageOption) apply(opts *options) {
	opts.resultsPerPage = int(r)
}

func WithResultsPerPage(resultsPerPage int) Option {
	return resultsPerPageOption(resultsPerPage)
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
		url:            defaultURL,
		nvdURL:         defaultNVDURL,
		cveURL:         defaultCVEURL,
		dir:            filepath.Join(util.CacheDir(), "fetch", "openssh", "security"),
		retry:          3,
		concurrency:    5,
		wait:           1 * time.Second,
		resultsPerPage: nvdResultsPerPageMax,
	}

	for _, o := range opts {
		o.apply(options)
	}

	// raw/ is what this adds to the keep set. Every other fetcher calls
	// util.RemoveAll(options.dir) bare, which would take with it the
	// model-converted records this source exists to carry and no fetch can
	// rebuild. .git is named alongside it because WithKeep states the whole
	// set, and dropping it would discard the history the tree is distributed
	// as.
	//
	// The rest of the tree is still swept, rather than narrowing this to the
	// origin/ the fetch does own: that would leave anything written outside it
	// to accumulate, including a file an older version of this fetcher wrote
	// and the current one no longer does. The skill below is one such file, and
	// is rewritten straight after.
	if err := util.RemoveAll(options.dir, util.WithKeep(".git", "raw")); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch OpenSSH Security Advisory")
	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	if err := options.writeSkill(); err != nil {
		return errors.Wrap(err, "write skill")
	}

	return nil
}

func (opts options) fetch() error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	bs, err := get(client, opts.url)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", opts.url)
	}

	// The page is one list and nothing else, so entries going missing means the
	// retrieval went wrong -- a captive portal, an error page served with a
	// 200, a truncated body. Storing that would present as upstream having
	// deleted its security history, and the conversion step downstream would
	// follow it into deleting raw/.
	if err := validate(bs); err != nil {
		return errors.Wrapf(err, "validate %s", opts.url)
	}

	// Stored as served: no fetch timestamp, no ETag, no status line. Those
	// change on every run even when the page does not, and would turn each
	// fetch into a diff -- drowning the one signal this tree carries, that
	// OpenSSH revised the page.
	if err := write(filepath.Join(opts.dir, "origin", "security.html"), bs); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "origin", "security.html"))
	}

	docs, err := cited(bs, opts.url)
	if err != nil {
		return errors.Wrapf(err, "collect documents cited by %s", opts.url)
	}
	for _, d := range docs {
		bs, err := get(client, d.url)
		if err != nil {
			// Not fatal, deliberately. These documents go back to 2000 and
			// OpenSSH is under no obligation to keep serving all of them, so a
			// fetch that failed whenever one 404ed would stop delivering the
			// page over evidence for an advisory published 25 years ago. What
			// is lost is the ability to annotate from that document, and the
			// conversion step sees that for itself: it cites what is under
			// origin/, so a document that is not there is not citable.
			slog.Warn("skip document cited by the page", slog.String("url", d.url), slog.String("err", err.Error()))
			continue
		}

		if err := write(filepath.Join(opts.dir, "origin", d.path), bs); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "origin", d.path))
		}
	}

	if err := opts.fetchCVEs(client); err != nil {
		return errors.Wrap(err, "fetch cve records")
	}

	return nil
}

// fetchCVEs stores the CVE records for OpenSSH under origin/mitre/.
//
// They are here because the page does not carry CVE IDs and neither do the
// documents it links: six of the 55 entries name one, and of the remaining 49
// exactly one has a linked release note that names an ID -- and that one,
// CVE-2020-14871 in release-8.5, is Solaris' rather than OpenSSH's. The reason
// is structural: OpenSSH is not a CNA, so the IDs are assigned elsewhere, by
// Red Hat or by MITRE, and the project's own documents predate or ignore them.
// The ID an advisory is filed under is therefore only knowable from the CVE
// list, which is what makes this the evidence for that one claim.
//
// Enumeration failure is fatal, unlike a single missing record. The tree was
// emptied before this ran, so continuing past it would commit an origin/mitre/
// that is empty for a reason no reader could distinguish from OpenSSH having
// no CVEs at all -- and would break every annotation already resting on it.
func (opts options) fetchCVEs(client *utilhttp.Client) error {
	ids, err := opts.cveIDs(client)
	if err != nil {
		return errors.Wrap(err, "list cve ids")
	}

	slog.Info("Fetch CVE records", slog.Int("count", len(ids)))

	us := make([]string, 0, len(ids))
	for _, id := range ids {
		u, err := url.JoinPath(opts.cveURL, id)
		if err != nil {
			return errors.Wrapf(err, "join %s and %s", opts.cveURL, id)
		}
		us = append(us, u)
	}

	if err := client.PipelineGet(us, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		id := path.Base(resp.Request.URL.Path)

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			// One record being unavailable is not the run's problem: the ID
			// came from NVD and cve.org may not serve it (a reserved or
			// rejected record). The conversion step sees it for itself, since
			// it cites what is under origin/.
			slog.Warn("skip cve record", slog.String("id", id), slog.Int("status", resp.StatusCode))
			return nil
		}

		bs, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "read %s", resp.Request.URL)
		}

		if err := write(filepath.Join(opts.dir, "origin", "mitre", fmt.Sprintf("%s.json", id)), bs); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "origin", "mitre", fmt.Sprintf("%s.json", id)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

// cveIDs asks NVD which CVE IDs are OpenSSH's, by CPE and by keyword, and
// returns the union.
//
// Both are needed. The CPE query is the precise one -- it asks for records NVD
// has matched to cpe:2.3:a:openbsd:openssh -- but that matching is analyst work
// NVD has been behind on since 2024, and a record awaiting it is simply absent:
// CVE-2024-39894, the ObscureKeystrokeTiming advisory of 2024-07-01, is one.
// The keyword query catches those and is the wider net, at the cost of records
// that merely mention OpenSSH in passing. Storing a few extra records costs a
// file each; missing one costs an advisory its ID, with nothing to show that it
// was missed.
func (opts options) cveIDs(client *utilhttp.Client) ([]string, error) {
	ids := make(map[string]struct{})
	for _, q := range []string{
		fmt.Sprintf("virtualMatchString=%s", url.QueryEscape("cpe:2.3:a:openbsd:openssh")),
		fmt.Sprintf("keywordSearch=%s", url.QueryEscape("OpenSSH")),
	} {
		// Paged, though both queries answer in one page today -- 134 and 177
		// against a 2,000 ceiling. The margin is wide but it is not a reason to
		// read one page and stop: what a truncated list costs is not an error
		// but a set of advisories that quietly cannot be annotated, and the
		// keyword query grows with every CVE that so much as mentions OpenSSH.
		for startIndex := 0; ; {
			u := fmt.Sprintf("%s?%s&startIndex=%d&resultsPerPage=%d", opts.nvdURL, q, startIndex, opts.resultsPerPage)

			bs, err := get(client, u)
			if err != nil {
				return nil, errors.Wrapf(err, "fetch %s", u)
			}

			var r nvdResponse
			if err := json.Unmarshal(bs, &r); err != nil {
				return nil, errors.Wrapf(err, "decode %s", u)
			}

			for _, v := range r.Vulnerabilities {
				if cveIDPattern.MatchString(v.CVE.ID) {
					ids[v.CVE.ID] = struct{}{}
				}
			}

			startIndex += len(r.Vulnerabilities)
			if startIndex >= r.TotalResults {
				break
			}

			// A page that advances nothing while claiming more would spin here
			// forever.
			if len(r.Vulnerabilities) == 0 {
				return nil, errors.Errorf("unexpected empty page. expected: %q, actual: %q", fmt.Sprintf("some of the %d results remaining after %d", r.TotalResults, startIndex), "none")
			}

			time.Sleep(opts.wait)
		}

		time.Sleep(opts.wait)
	}

	return slices.Sorted(maps.Keys(ids)), nil
}

// nvdResponse is the part of the NVD API's answer this needs: the IDs, and
// enough to tell a complete page from a truncated one.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID string `json:"id"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// cveIDPattern is the shape an ID has to have before it becomes a path element.
var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// get returns a response body.
//
// It returns the bytes rather than decoding, or handing back the response for
// the caller to stream: what goes to origin/ has to be what was served, so two
// of the three callers need the bytes, and a second helper for the third would
// split the status check across both. The one body it only decodes is an NVD
// page of a few hundred kilobytes, which is not worth a second shape for.
func get(client *utilhttp.Client, u string) ([]byte, error) {
	resp, err := client.Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", u)
	}

	return bs, nil
}

// document is a document the page cites, and the path it is stored at under
// origin/.
type document struct {
	url  string
	path string
}

// cited returns the documents linked from the page that are stored beside it.
//
// It is scoped to the page's own host and to /txt/, where OpenSSH keeps its
// release notes and advisories -- the 35 documents that carry the fix releases
// and the detail the entries compress. Not the CVE IDs: five of the 35 name one
// at all, and those five are the ones the page already names itself. Those come
// from the CVE List instead, stored under origin/mitre/ by fetchCVEs, for the
// structural reason given there.
//
// The scope is a boundary rather than a shortcut. These are published by the
// project that publishes the page, so a diff against a stored copy carries the
// same meaning here as it does for the page; whereas the entries also link a
// dozen third-party hosts, several long dead (bindview, corest, cpni), whose
// retrieval would fail or vary run to run without adding evidence -- a
// cve.mitre.org link states the CVE ID that is already its own anchor text, and
// the kb.cert.org notes are about SSH at large, mostly attached to the entries
// recording that OpenSSH was never affected and which must therefore gain no
// CVE at all.
func cited(page []byte, base string) ([]document, error) {
	b, err := url.Parse(base)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", base)
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(page))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var ds []document
	seen := make(map[string]struct{})
	d.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if !ok {
			return
		}

		u, err := b.Parse(href)
		if err != nil || u.Host != b.Host || !strings.HasPrefix(u.Path, "/txt/") {
			return
		}

		// The path is what the document is stored as, so it has to be usable as
		// one: a traversal or a directory would write outside origin/ or over
		// the tree it is meant to fill.
		p := filepath.FromSlash(strings.TrimPrefix(u.Path, "/"))
		if p != filepath.Clean(p) || strings.HasPrefix(p, "..") || strings.HasSuffix(u.Path, "/") {
			return
		}

		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}

		u.Fragment, u.RawQuery = "", ""
		ds = append(ds, document{url: u.String(), path: p})
	})

	return ds, nil
}

// validate rejects a body that is not the security page.
//
// Both the title and the entry count are checked: the title alone is carried by
// nothing else on the site but says nothing about whether the list survived the
// transfer, and a body can hold plenty of list items without being this page.
// The title is matched loosely -- OpenSSH has titled it "OpenSSH: Security"
// throughout, but the name in it is the part that identifies the page, and
// pinning the rest would fail the fetch over a wording change that costs the
// conversion downstream nothing.
func validate(bs []byte) error {
	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return errors.Wrap(err, "parse as html")
	}

	if title := strings.TrimSpace(d.Find("title").First().Text()); !strings.Contains(title, "OpenSSH") {
		return errors.Errorf("unexpected title. expected: %q, actual: %q", "a title naming OpenSSH", title)
	}

	if n := d.Find("li").Length(); n < minEntries {
		return errors.Errorf("unexpected number of entries. expected: %q, actual: %d", fmt.Sprintf(">= %d", minEntries), n)
	}

	return nil
}

// writeSkill puts the conversion instructions beside the page they describe, so
// that origin/ is never in the tree without them.
//
// It is rewritten on every fetch rather than written once: the instructions and
// the raw schema they produce are versioned together in vuls-data-update, and a
// tree carrying last year's instructions beside this year's fetcher is the
// failure this avoids. Local edits are overwritten -- the file is output, and
// belongs upstream in skill/SKILL.md.
func (opts options) writeSkill() error {
	if err := write(filepath.Join(opts.dir, skillPath), skill); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, skillPath))
	}
	return nil
}

func write(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
	}

	if err := os.WriteFile(path, content, 0666); err != nil {
		return errors.Wrapf(err, "write %s", path)
	}

	return nil
}
