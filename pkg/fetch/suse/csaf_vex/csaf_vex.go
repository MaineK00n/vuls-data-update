package csaf_vex

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
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

func Fetch(years []string, opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "suse", "csaf-vex"),
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

	log.Println("[INFO] Fetch SUSE CSAF VEX")
	cves, err := options.walkIndexOf(years)
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}
	us := make([]string, 0, len(cves))
	for _, cve := range cves {
		u, err := url.JoinPath(options.baseURL, cve)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}
		us = append(us, u)
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(us, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error request response with status code %d", resp.StatusCode)
		}

		var adv CSAF
		if err := json.NewDecoder(resp.Body).Decode(&adv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		splitted, err := util.Split(adv.Document.Tracking.ID, "-", "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", adv.Document.Tracking.ID)
			return nil
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", adv.Document.Tracking.ID)
			return nil
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", adv.Document.Tracking.ID)), adv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", adv.Document.Tracking.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (opts options) walkIndexOf(years []string) ([]string, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var cves []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "cve-") {
			return
		}
		splitted, err := util.Split(txt, "-", "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "cve-yyyy-\\d{4,}.json", txt)
			return
		}
		if slices.Contains(years, splitted[1]) {
			cves = append(cves, txt)
		}
	})
	return cves, nil
}
