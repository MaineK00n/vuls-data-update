package cvrf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
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

	log.Println("[INFO] Fetch SUSE CVRF")
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

	oldCVEs := map[string]struct{}{}
	if err := filepath.WalkDir(options.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		_, f := filepath.Split(path)
		if !strings.HasPrefix(f, "CVE-") {
			return nil
		}

		oldCVEs[strings.TrimSuffix(f, ".json")] = struct{}{}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", options.dir)
	}

	for idx := range util.ChunkSlice(len(cveURLs), 1000) {
		resps, err := util.FetchConcurrently(cveURLs[idx.From:idx.To], options.concurrency, options.wait, options.retry)
		if err != nil {
			return errors.Wrap(err, "fetch concurrently")
		}

		for _, resp := range resps {
			var adv CVRF
			if err := xml.Unmarshal(resp, &adv); err != nil {
				return errors.Wrap(err, "xml unmarshal")
			}

			y := strings.Split(adv.Vulnerability.CVE, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				continue
			}

			if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", adv.Vulnerability.CVE)), adv); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", adv.Vulnerability.CVE)))
			}

			delete(oldCVEs, adv.Vulnerability.CVE)
		}
	}

	for cve := range oldCVEs {
		if err := os.Remove(filepath.Join(options.dir, fmt.Sprintf("%s.json", cve))); err != nil {
			return errors.Wrap(err, "remove old cve")
		}
	}

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
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "cvrf-CVE-") {
			return
		}
		cves = append(cves, txt)
	})
	return cves, nil
}
