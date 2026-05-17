package archive

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://learn.microsoft.com/en-us/security-updates/"

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

func WithBaseURL(u string) Option {
	return baseURLOption(u)
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
		dir:         filepath.Join(util.CacheDir(), "fetch", "microsoft", "bulletin", "archive"),
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

	slog.Info("Fetch Microsoft Bulletin Archive")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	refs, err := options.fetchTOC(client)
	if err != nil {
		return errors.Wrap(err, "fetch TOC")
	}

	urls := make([]string, 0, len(refs))
	for _, r := range refs {
		u, err := url.JoinPath(options.baseURL, "securitybulletins", r.Year, r.MSID)
		if err != nil {
			return errors.Wrap(err, "url join")
		}
		urls = append(urls, fmt.Sprintf("%s?accept=text/markdown", u))
	}

	if err := client.PipelineGet(urls, options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d, url: %s", resp.StatusCode, resp.Request.URL.String())
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "read response body")
		}

		year, msid, err := parseBulletinPath(resp.Request.URL.Path)
		if err != nil {
			return errors.Wrapf(err, "parse response url %q", resp.Request.URL.String())
		}

		arch := Archive{
			ID:       strings.ToUpper(msid),
			Year:     year,
			URL:      fmt.Sprintf("https://learn.microsoft.com/en-us/security-updates/securitybulletins/%s/%s", year, msid),
			Markdown: string(body),
		}

		yy := year[2:]
		out := filepath.Join(options.dir, yy, fmt.Sprintf("%s.json", strings.ToUpper(msid)))
		if err := util.Write(out, arch); err != nil {
			return errors.Wrapf(err, "write %s", out)
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (o options) fetchTOC(client *utilhttp.Client) ([]bulletinRef, error) {
	tocURL, err := url.JoinPath(o.baseURL, "toc.json")
	if err != nil {
		return nil, errors.Wrap(err, "url join")
	}

	resp, err := client.Get(tocURL)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", tocURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var toc tocNode
	if err := json.UnmarshalRead(resp.Body, &toc); err != nil {
		return nil, errors.Wrap(err, "decode TOC json")
	}

	var refs []bulletinRef
	var walk func(n *tocNode)
	walk = func(n *tocNode) {
		if n == nil {
			return
		}
		if year, msid, ok := splitBulletinHref(n.Href); ok {
			refs = append(refs, bulletinRef{Year: year, MSID: msid})
		}
		for _, c := range n.Items {
			walk(c)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(&toc)

	return refs, nil
}

// splitBulletinHref parses a TOC href of the form
// "securitybulletins/<year>/<msid>" into its year and msid components.
// Anything that doesn't match that exact two-segment shape under
// "securitybulletins/" is rejected.
func splitBulletinHref(href string) (year, msid string, ok bool) {
	const prefix = "securitybulletins/"
	rest, found := strings.CutPrefix(href, prefix)
	if !found {
		return "", "", false
	}
	year, msid, found = strings.Cut(rest, "/")
	if !found || strings.Contains(msid, "/") {
		return "", "", false
	}
	if !isBulletinYear(year) || !isBulletinMSID(msid) {
		return "", "", false
	}
	return year, msid, true
}

// parseBulletinPath extracts (year, msid) from a response URL path of the
// form ".../securitybulletins/<year>/<msid>".
func parseBulletinPath(p string) (year, msid string, err error) {
	msid = path.Base(p)
	dir := path.Dir(p)
	year = path.Base(dir)
	parent := path.Base(path.Dir(dir))
	if parent != "securitybulletins" || !isBulletinYear(year) || !isBulletinMSID(msid) {
		return "", "", errors.Errorf("unexpected response path, want %q, got %q", ".../securitybulletins/<year>/ms<yy>-<nnn>", p)
	}
	return year, msid, nil
}

// isBulletinYear reports whether s is a 4-digit year.
func isBulletinYear(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isBulletinMSID reports whether s matches the canonical "ms<yy>-<nnn>"
// bulletin identifier shape (lowercase).
func isBulletinMSID(s string) bool {
	if len(s) != 9 {
		return false
	}
	if s[0] != 'm' || s[1] != 's' || s[4] != '-' {
		return false
	}
	for _, i := range []int{2, 3, 5, 6, 7, 8} {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
