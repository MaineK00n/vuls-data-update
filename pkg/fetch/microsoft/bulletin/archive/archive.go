package archive

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	tocURL      = "https://learn.microsoft.com/en-us/security-updates/toc.json"
	pageBaseURL = "https://learn.microsoft.com/en-us/security-updates/"
)

var (
	tocHrefRE     = regexp.MustCompile(`^securitybulletins/(\d{4})/(ms\d{2}-\d{3})$`)
	responseURLRE = regexp.MustCompile(`/securitybulletins/(\d{4})/(ms\d{2}-\d{3})$`)
)

type options struct {
	tocURL      string
	pageBaseURL string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
}

type Option interface {
	apply(*options)
}

type tocURLOption string

func (u tocURLOption) apply(opts *options) {
	opts.tocURL = string(u)
}

func WithTOCURL(u string) Option {
	return tocURLOption(u)
}

type pageBaseURLOption string

func (u pageBaseURLOption) apply(opts *options) {
	opts.pageBaseURL = string(u)
}

func WithPageBaseURL(u string) Option {
	return pageBaseURLOption(u)
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
		tocURL:      tocURL,
		pageBaseURL: pageBaseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "microsoft", "bulletinarchive"),
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
		u, err := url.JoinPath(options.pageBaseURL, "securitybulletins", r.Year, r.MSID)
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

		m := responseURLRE.FindStringSubmatch(resp.Request.URL.Path)
		if m == nil {
			return errors.Errorf("unexpected response URL. expected: %q, actual: %q", ".../securitybulletins/<year>/ms<yy>-<nnn>", resp.Request.URL.String())
		}
		year, msid := m[1], m[2]

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

type bulletinRef struct {
	Year string
	MSID string
}

type tocNode struct {
	Href     string     `json:"href"`
	Items    []*tocNode `json:"items"`
	Children []*tocNode `json:"children"`
}

func (o options) fetchTOC(client *utilhttp.Client) ([]bulletinRef, error) {
	resp, err := client.Get(o.tocURL)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", o.tocURL)
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
		if m := tocHrefRE.FindStringSubmatch(n.Href); m != nil {
			refs = append(refs, bulletinRef{Year: m[1], MSID: m[2]})
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
