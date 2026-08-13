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
// Which is also why origin/ holds more than the page. Six of the 55 entries
// name a CVE ID; the rest leave it to the release notes they link to, and the
// same goes for several of the fix releases. Those documents are stored under
// origin/txt/ so that a raw/ record can cite one and stay checkable on the
// terms above -- an annotation quotes a sentence, and the sentence is in the
// repository. Storing only the page would leave every such claim resting on a
// document that may since have been revised, with nothing here to notice.
//
// Hence what Fetch is careful about: it replaces origin/ and leaves everything
// else in the output directory alone. raw/ is the expensive part of this tree
// and is not the fetcher's to discard.
package security

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const defaultURL = "https://www.openssh.com/security.html"

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
	url   string
	dir   string
	retry int
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
		url:   defaultURL,
		dir:   filepath.Join(util.CacheDir(), "fetch", "openssh", "security"),
		retry: 3,
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

	return nil
}

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
// release notes and advisories -- the 35 documents that between them state the
// CVE IDs and fix releases the entries themselves mostly leave out. The scope
// is a boundary rather than a shortcut. These are published by the project that
// publishes the page, so a diff against a stored copy carries the same meaning
// here as it does for the page; whereas the entries also link a dozen
// third-party hosts, several long dead (bindview, corest, cpni), whose
// retrieval would fail or vary run to run without adding evidence -- a
// cve.mitre.org link states the CVE ID that is already its own anchor text, and
// the kb.cert.org notes are about SSH at large, mostly attached to the entries
// recording that OpenSSH was never affected and which must therefore gain no
// CVE at all.
//
// A document outside the scope can still be cited by an annotation, which names
// a URL whether or not it is stored here. What it cannot be is offline-checkable.
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
