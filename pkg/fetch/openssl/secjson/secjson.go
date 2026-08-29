package secjson

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://openssl-library.org/news/secjson/"

const statementsFilename = "statements.json"

// Pattern defined by the CVE Record Format
// https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
var cveIDPattern = regexp.MustCompile(`^CVE-([0-9]{4})-[0-9]{4,}$`)

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
}

type Option interface {
	apply(*options)
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
		dir:         filepath.Join(util.CacheDir(), "fetch", "openssl", "secjson"),
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

	slog.Info("Fetch OpenSSL Security Advisory (JSON)")
	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (opts options) fetch() error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry), utilhttp.WithClientHTTPClient(opts.httpClient))

	statementsURL, cveURLs, err := opts.fetchIndexOf(client)
	if err != nil {
		return errors.Wrap(err, "fetch index of")
	}

	if statementsURL == "" {
		return errors.Errorf("%s not found in %s", statementsFilename, opts.baseURL)
	}
	if err := opts.fetchStatements(client, statementsURL); err != nil {
		return errors.Wrap(err, "fetch statements")
	}

	if err := client.PipelineGet(cveURLs, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d for %q", resp.StatusCode, path.Base(resp.Request.URL.Path))
		}

		var v CVE
		if err := json.UnmarshalRead(resp.Body, &v); err != nil {
			return errors.Wrap(err, "decode json")
		}

		// The ID comes from the remote payload and is used as a path element,
		// so accept only the format the schema defines.
		m := cveIDPattern.FindStringSubmatch(v.CVEMetadata.CVEID)
		if m == nil {
			return errors.Errorf("unexpected ID format. expected: %q, actual: %q", cveIDPattern.String(), v.CVEMetadata.CVEID)
		}

		if err := util.Write(filepath.Join(opts.dir, m[1], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, m[1], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

// fetchIndexOf collects the JSON files linked from the index page. It returns
// the statements.json URL, which is empty if the page does not link it, and the
// URLs of the per-CVE records. A linked JSON file matching neither is an error,
// so that additions to the data set surface instead of being silently dropped.
func (opts options) fetchIndexOf(client *utilhttp.Client) (string, []string, error) {
	resp, err := client.Get(opts.baseURL)
	if err != nil {
		return "", nil, errors.Wrapf(err, "fetch %s", opts.baseURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", nil, errors.Wrap(err, "parse as html")
	}

	var (
		statementsURL string
		cveURLs       []string
	)
	for _, s := range d.Find("main a").EachIter() {
		href, ok := s.Attr("href")
		if !ok {
			continue
		}

		ref, err := url.Parse(href)
		if err != nil {
			return "", nil, errors.Wrapf(err, "parse %s", href)
		}
		u := resp.Request.URL.ResolveReference(ref)

		switch b := path.Base(u.Path); {
		case path.Ext(b) == ".json":
			switch {
			case b == statementsFilename:
				statementsURL = u.String()
			case strings.HasPrefix(b, "cve-"):
				cveURLs = append(cveURLs, u.String())
			default:
				return "", nil, errors.Errorf("unexpected json file name. expected: %q, actual: %q", []string{statementsFilename, "cve-yyyy-\\d{4,}.json"}, b)
			}
		default:
			continue
		}
	}

	return statementsURL, cveURLs, nil
}

func (opts options) fetchStatements(client *utilhttp.Client, u string) error {
	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var ss Statements
	if err := json.UnmarshalRead(resp.Body, &ss); err != nil {
		return errors.Wrap(err, "decode json")
	}

	if err := util.Write(filepath.Join(opts.dir, statementsFilename), ss); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, statementsFilename))
	}

	return nil
}
