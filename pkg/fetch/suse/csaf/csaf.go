package csaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://ftp.suse.com/pub/projects/security/csaf-vex/"

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
		dir:         filepath.Join(util.CacheDir(), "suse", "csaf"),
		retry:       3,
		concurrency: 20,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch SUSE CSAF")
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

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	for idx := range util.ChunkSlice(len(cveURLs), 1000) {
		resps, err := client.MultiGet(cveURLs[idx.From:idx.To], options.concurrency, options.wait)
		if err != nil {
			return errors.Wrap(err, "fetch concurrently")
		}

		for _, resp := range resps {
			var adv CSAF
			if err := json.Unmarshal(resp, &adv); err != nil {
				return errors.Wrap(err, "json unmarshal")
			}

			splitted, err := util.Split(adv.Document.Tracking.ID, "-", "-")
			if err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", adv.Document.Tracking.ID)
				continue
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", adv.Document.Tracking.ID)
				continue
			}

			if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", adv.Document.Tracking.ID)), adv); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", adv.Document.Tracking.ID)))
			}
		}
	}

	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
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
		if !strings.HasPrefix(txt, "cve-") {
			return
		}
		cves = append(cves, txt)
	})
	return cves, nil
}
