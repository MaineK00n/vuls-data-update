package vex

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://access.redhat.com/security/data/csaf/beta/vex/"

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
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

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		dataURL:     dataURL,
		dir:         filepath.Join(util.CacheDir(), "redhat", "vex"),
		retry:       3,
		concurrency: 10,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch RedHat CSAF VEX")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	u, err := url.JoinPath(options.dataURL, "index.txt")
	if err != nil {
		return errors.Wrap(err, "url join")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var urls []string
	s := bufio.NewScanner(resp.Body)
	for s.Scan() {
		t := s.Text()
		if t == "" {
			continue
		}

		u, err := url.JoinPath(options.dataURL, t)
		if err != nil {
			return errors.Wrap(err, "url join")
		}
		urls = append(urls, u)
	}

	if err := client.PipelineGet(urls, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error request response with status code %d", resp.StatusCode)
		}

		var vex VEX
		if err := json.NewDecoder(resp.Body).Decode(&vex); err != nil {
			return errors.Wrap(err, "decode json")
		}

		splitted, err := util.Split(vex.Document.Tracking.ID, "-", "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
			return nil
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
			return nil
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)), vex); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
