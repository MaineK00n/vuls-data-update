package cvrf

import (
	"bytes"
	"encoding/xml"
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

const baseURL = "https://ftp.suse.com/pub/projects/security/cvrf1.2/"

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
		dir:         filepath.Join(util.CacheDir(), "suse", "cvrf"),
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

	log.Println("[INFO] Fetch SUSE CVRF")
	cvrfs, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}
	us := make([]string, 0, len(cvrfs))
	for _, cvrf := range cvrfs {
		u, err := url.JoinPath(options.baseURL, cvrf)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}
		us = append(us, u)
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(us, options.concurrency, options.wait, func(resp utilhttp.Response) error {
		var adv CVRF
		if err := xml.Unmarshal(resp.Body, &adv); err != nil {
			return errors.Wrap(err, "xml unmarshal")
		}

		id := adv.DocumentTracking.Identification.ID
		if adv.DocumentType == "SUSE Image" {
			id = adv.DocumentTitle
		}

		splitted, err := util.Split(id, "-", "-", "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "(SUSE|openSUSE)-SU-yyyy:\\d+-1", id)
			return nil
		}

		if _, err := time.Parse("2006", strings.Split(splitted[2], ":")[0]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "(SUSE|openSUSE)-SU-yyyy:\\d+-1", id)
			return nil
		}

		if err := util.Write(filepath.Join(options.dir, strings.Split(id, "-")[0], strings.Split(splitted[2], ":")[0], fmt.Sprintf("%s.json", id)), adv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, strings.Split(id, "-")[0], strings.Split(splitted[2], ":")[0], fmt.Sprintf("%s.json", id)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
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

	var cs []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "cvrf-") {
			return
		}
		cs = append(cs, txt)
	})
	return cs, nil
}
