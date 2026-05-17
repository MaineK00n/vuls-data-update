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
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://learn.microsoft.com/en-us/security-updates"

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

	msids, err := options.fetchTOC(client)
	if err != nil {
		return errors.Wrap(err, "fetch TOC")
	}

	urls := make([]string, 0, len(msids))
	for _, msid := range msids {
		u, err := url.JoinPath(options.baseURL, "securitybulletins", yearOfMSID(msid), msid)
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

		msid, err := parseBulletinPath(resp.Request.URL.Path)
		if err != nil {
			return errors.Wrapf(err, "parse response url %q", resp.Request.URL.String())
		}

		year := yearOfMSID(msid)
		upperMSID := strings.ToUpper(msid)

		arch := Archive{
			ID:       upperMSID,
			Year:     year,
			URL:      fmt.Sprintf("https://learn.microsoft.com/en-us/security-updates/securitybulletins/%s/%s", year, msid),
			Markdown: string(body),
		}

		out := filepath.Join(options.dir, msid[2:4], fmt.Sprintf("%s.json", upperMSID))
		if err := util.Write(out, arch); err != nil {
			return errors.Wrapf(err, "write %s", out)
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (o options) fetchTOC(client *utilhttp.Client) ([]string, error) {
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

	var msids []string
	var walk func(n *tocNode)
	walk = func(n *tocNode) {
		if n == nil {
			return
		}
		if msid, ok := splitBulletinHref(n.Href); ok {
			msids = append(msids, msid)
		}
		for _, c := range n.Items {
			walk(c)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(&toc)

	return msids, nil
}

// splitBulletinHref returns the bulletin msid from a TOC href of the form
// "securitybulletins/<year>/<msid>". The middle <year> segment is not
// validated because the year is already encoded in the msid.
func splitBulletinHref(href string) (string, bool) {
	rest, ok := strings.CutPrefix(href, "securitybulletins/")
	if !ok {
		return "", false
	}
	_, msid, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(msid, "/") {
		return "", false
	}
	if !isBulletinMSID(msid) {
		return "", false
	}
	return msid, true
}

// parseBulletinPath extracts the bulletin msid from a response URL path of
// the form ".../securitybulletins/<year>/<msid>".
func parseBulletinPath(p string) (string, error) {
	msid := path.Base(p)
	if path.Base(path.Dir(path.Dir(p))) != "securitybulletins" || !isBulletinMSID(msid) {
		return "", errors.Errorf("unexpected response path, want %q, got %q", ".../securitybulletins/<year>/ms<yy>-<nnn>", p)
	}
	return msid, nil
}

// isBulletinMSID reports whether s is a canonical "ms<yy>-<nnn>" bulletin ID.
func isBulletinMSID(s string) bool {
	lhs, rhs, ok := strings.Cut(s, "-")
	if !ok || len(rhs) != 3 {
		return false
	}
	yy, ok := strings.CutPrefix(lhs, "ms")
	if !ok {
		return false
	}
	if _, err := time.Parse("06", yy); err != nil {
		return false
	}
	if _, err := strconv.ParseUint(rhs, 10, 64); err != nil {
		return false
	}
	return true
}

// yearOfMSID returns the 4-digit year encoded in a validated msid's <yy>.
// Go's "06" format maps yy >= 69 to 19xx and yy < 69 to 20xx, which spans
// the Microsoft Security Bulletin range (ms98-001 through ms17-006).
func yearOfMSID(msid string) string {
	t, _ := time.Parse("06", msid[2:4])
	return strconv.Itoa(t.Year())
}
