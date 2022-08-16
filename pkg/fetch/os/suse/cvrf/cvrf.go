package cvrf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const baseURL = "https://ftp.suse.com/pub/projects/security/cvrf-cve/"

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
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

type waitOption int

func (w waitOption) apply(opts *options) {
	opts.wait = int(w)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.SourceDir(), "suse", "cvrf"),
		retry:       3,
		concurrency: 20,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	cves, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}
	cveURLs := make([]string, 0, len(cves))
	for _, cve := range cves {
		u, err := url.JoinPath(options.baseURL, cve)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}
		cveURLs = append(cveURLs, u)
	}

	resps, err := util.FetchConcurrently(cveURLs, options.concurrency, options.wait, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch concurrently")
	}

	advs := make([]CVRF, 0, len(resps))
	for _, resp := range resps {
		var a CVRF
		if err := xml.Unmarshal(resp, &a); err != nil {
			return errors.Wrap(err, "xml unmarshal")
		}
		advs = append(advs, a)
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}
	bar := pb.StartNew(len(advs))
	for _, adv := range advs {
		if err := func() error {
			y := strings.Split(adv.Vulnerability.CVE, "-")[1]

			if err := os.MkdirAll(filepath.Join(options.dir, y), os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Join(options.dir, y))
			}

			f, err := os.Create(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", adv.Vulnerability.CVE)))
			if err != nil {
				return errors.Wrapf(err, "create %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", adv.Vulnerability.CVE)))
			}
			defer f.Close()

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(adv); err != nil {
				return errors.Wrap(err, "encode data")
			}
			return nil
		}(); err != nil {
			return err
		}

		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	bs, err := util.FetchURL(opts.baseURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var cves []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "cvrf-CVE-") {
			return
		}
		cves = append(cves, txt)
	})
	return cves, nil
}
