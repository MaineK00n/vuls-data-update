package csaf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://fortiguard.fortinet.com/psirt/%s"

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

func Fetch(args []string, opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "fortinet", "csaf"),
		retry:       3,
		concurrency: 3,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	if err := options.fetch(args); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (opts options) fetch(ids []string) error {
	log.Printf("[INFO] Fetch Fortinet CSAF")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	bar := pb.StartNew(len(ids))
	g, _ := errgroup.WithContext(context.TODO())
	g.SetLimit(opts.concurrency)
	for _, id := range ids {
		g.Go(func() error {
			defer func() {
				time.Sleep(opts.wait)
				bar.Increment()
			}()

			u, err := opts.fetchCSAFURL(client, id)
			if err != nil {
				return errors.Wrap(err, "fetch csaf url")
			}
			time.Sleep(opts.wait)

			if err := opts.fetchCSAF(client, u); err != nil {
				return errors.Wrap(err, "fetch csaf")
			}

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	bar.Finish()

	return nil
}

func (opts options) fetchCSAFURL(client *utilhttp.Client, id string) (string, error) {
	resp, err := client.Get(fmt.Sprintf(opts.baseURL, id))
	if err != nil {
		return "", errors.Wrapf(err, "fetch %s", fmt.Sprintf(opts.baseURL, id))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "create new document from reader")
	}

	var u string
	for _, tr := range doc.Find("div.sidebar table tr").EachIter() {
		td := tr.Find("td")
		if td.Length() != 2 {
			return "", errors.Errorf("unexpected table data cell length. expected: %d, actual: %d", 2, td.Length())
		}
		switch td.Eq(0).Text() {
		case "Download":
			for _, a := range td.Find("p > a").EachIter() {
				href, ok := a.Attr("href")
				if !ok {
					return "", errors.New("href attribute not found in anchor tag")
				}

				switch {
				case strings.HasPrefix(href, "/psirt/cvrf/"), strings.HasPrefix(href, "/psirt/stix/"):
					continue
				case strings.HasPrefix(href, "/psirt/csaf/"):
					_, rhs, ok := strings.Cut(href, "?csaf_url=")
					if !ok {
						return "", errors.Errorf("unexpected CSAF href format. expected: %q, actual: %q", "/psirt/csaf/<Advisory ID>?csaf_url=<CSAF URL>", href)
					}
					u = rhs
				default:
					return "", errors.Errorf("unexpected download href format. expected: %q, actual: %q", []string{"/psirt/cvrf/<Advisory ID>", "/psirt/csaf/<Advisory ID>?csaf_url=<CSAF URL>", "/psirt/stix/<Advisory ID>?stix_url=<STIX URL>"}, href)
				}
			}
		default:
			continue
		}
	}
	if u == "" {
		return "", errors.New("CSAF download URL not found")
	}
	return u, nil
}

func (opts options) fetchCSAF(client *utilhttp.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var a CSAF
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return errors.Wrap(err, "decode json")
	}

	ss, err := util.Split(a.Document.Tracking.ID, "-", "-", "-")
	if err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "FG-IR-yy-\\d+", a.Document.Tracking.ID)
	}
	t, err := time.Parse("06", ss[2])
	if err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "FG-IR-yy-\\d+", a.Document.Tracking.ID)
	}

	if err := util.Write(filepath.Join(opts.dir, t.Format("2006"), fmt.Sprintf("%s.json", a.Document.Tracking.ID)), a); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, t.Format("2006"), fmt.Sprintf("%s.json", a.Document.Tracking.ID)))
	}

	return nil
}
