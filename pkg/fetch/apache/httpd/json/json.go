package json

import (
	"bytes"
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

const baseURL = "https://httpd.apache.org/security/json/"

// Pattern defined by the CVE Record Format
// https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
var cveIDPattern = regexp.MustCompile(`^CVE-([0-9]{4})-[0-9]{4,}$`)

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "apache", "httpd", "json"),
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

	slog.Info("Fetch Apache HTTP Server CVE (JSON)")
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
		return errors.Errorf("no cve record found in %s", opts.baseURL)
	}

	if err := client.PipelineGet(us, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d for %q", resp.StatusCode, path.Base(resp.Request.URL.Path))
		}

		bs, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "read %s", path.Base(resp.Request.URL.Path))
		}

		id, record, err := decode(bs)
		if err != nil {
			return errors.Wrapf(err, "decode %s", path.Base(resp.Request.URL.Path))
		}

		// The ID comes from the remote payload and is used as a path element,
		// so accept only the format the schema defines.
		m := cveIDPattern.FindStringSubmatch(id)
		if m == nil {
			return errors.Errorf("unexpected ID format. expected: %q, actual: %q", cveIDPattern.String(), id)
		}

		if err := util.Write(filepath.Join(opts.dir, m[1], fmt.Sprintf("%s.json", id)), record); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, m[1], fmt.Sprintf("%s.json", id)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

// fetchIndexOf collects the per-CVE JSON files linked from the directory index.
// A linked JSON file whose name is not a CVE ID is an error, so that additions
// to the data set surface instead of being silently dropped.
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

	as := d.Find("a")
	us := make([]string, 0, as.Length())
	for _, s := range as.EachIter() {
		href, ok := s.Attr("href")
		if !ok {
			continue
		}

		ref, err := url.Parse(href)
		if err != nil {
			return nil, errors.Wrapf(err, "parse %s", href)
		}
		u := resp.Request.URL.ResolveReference(ref)

		// The index also links the parent directory and the column sort
		// controls, neither of which resolves to a JSON file.
		b := path.Base(u.Path)
		if path.Ext(b) != ".json" {
			continue
		}

		if !cveIDPattern.MatchString(strings.TrimSuffix(b, ".json")) {
			return nil, errors.Errorf("unexpected json file name. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}.json", b)
		}

		us = append(us, u.String())
	}

	return us, nil
}

// decode picks the schema the record is written in and returns its CVE ID along
// with the decoded record. The two generations are told apart by which version
// member they carry; a record with neither is an error, so that a further
// generation surfaces instead of being decoded into the wrong shape.
func decode(bs []byte) (string, any, error) {
	var probe struct {
		DataVersion4 string `json:"data_version"`
		DataVersion5 string `json:"dataVersion"`
	}
	if err := json.UnmarshalRead(bytes.NewReader(bs), &probe); err != nil {
		return "", nil, errors.Wrap(err, "decode json")
	}

	switch {
	case probe.DataVersion5 != "":
		var v CVE5
		if err := json.UnmarshalRead(bytes.NewReader(bs), &v); err != nil {
			return "", nil, errors.Wrap(err, "decode cve record format")
		}
		return v.CVEMetadata.CVEID, v, nil
	case probe.DataVersion4 != "":
		var v CVE4
		if err := json.UnmarshalRead(bytes.NewReader(bs), &v); err != nil {
			return "", nil, errors.Wrap(err, "decode cve json 4.0")
		}
		return v.CVEDataMeta.ID, v, nil
	default:
		return "", nil, errors.Errorf("unexpected schema. expected one of: %q", []string{"data_version", "dataVersion"})
	}
}
