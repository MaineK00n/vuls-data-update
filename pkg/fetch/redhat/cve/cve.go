package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://access.redhat.com/hydra/rest/securitydata/cve.json?page=%d&after=%s&before=%s&per_page=1000"

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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
		dataURL:     dataURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "redhat", "cve"),
		retry:       20,
		concurrency: 15,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch RedHat CVE API")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	log.Printf("[INFO] Fetch RedHat 1996...%d CVEs", time.Now().Year())
	urls, err := options.list(client)
	if err != nil {
		return errors.Wrap(err, "list cve url")
	}

	log.Println("[INFO] Fetch RedHat CVEs")
	if err := client.PipelineGet(urls, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var cve CVE
		if err := json.NewDecoder(resp.Body).Decode(&cve); err != nil {
			return errors.Wrap(err, "decode json")
		}

		splitted, err := util.Split(cve.Name, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.Name)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.Name)
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", cve.Name)), cve); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", cve.Name)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (opts options) list(client *utilhttp.Client) ([]string, error) {
	var ys []int
	for y := 1996; y <= time.Now().Year(); y++ {
		ys = append(ys, y)
	}

	yearChan := make(chan int)
	go func() {
		defer close(yearChan)
		for _, y := range ys {
			yearChan <- y
		}
	}()

	bar := pb.Full.Start(len(ys))
	urlsChan := make(chan []string, len(ys))
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(opts.concurrency)
	for y := range yearChan {
		y := y

		g.Go(func() error {
			var us []string
			for page := 1; ; page++ {
				es, err := func() ([]entry, error) {
					resp, err := client.Get(fmt.Sprintf(opts.dataURL, page, time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"), time.Date(y+1, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")))
					if err != nil {
						return nil, errors.Wrapf(err, "fetch %s", fmt.Sprintf(opts.dataURL, page, time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"), time.Date(y+1, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")))
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						_, _ = io.Copy(io.Discard, resp.Body)
						return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
					}

					var es []entry
					if err := json.NewDecoder(resp.Body).Decode(&es); err != nil {
						return nil, errors.Wrap(err, "decode json")
					}

					return es, nil
				}()
				if err != nil {
					return errors.Wrapf(err, "list %d %d page", y, page)
				}

				if len(es) == 0 {
					break
				}

				for _, e := range es {
					us = append(us, e.ResourceURL)
				}

				time.Sleep(time.Duration(opts.wait) * time.Second)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				urlsChan <- us
				bar.Increment()
				return nil
			}
		})
	}
	if err := g.Wait(); err != nil {
		return nil, errors.Wrap(err, "err in goroutine")
	}
	close(urlsChan)
	bar.Finish()

	var urls []string
	for us := range urlsChan {
		urls = append(urls, us...)
	}

	return urls, nil
}
