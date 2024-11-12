package cvrf

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://www.fortiguard.com/psirt/cvrf/%s"

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

func Fetch(args []string, opts ...Option) error {
	options := &options{
		dataURL:     dataURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "fortinet"),
		retry:       3,
		concurrency: 4,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Fortinet")

	urls := make([]string, 0, len(args))
	for _, arg := range args {
		urls = append(urls, fmt.Sprintf(options.dataURL, arg))
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(urls, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error request response with status code %d", resp.StatusCode)
		}

		var a CVRF
		if err := xml.NewDecoder(resp.Body).Decode(&a); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		ss, err := util.Split(a.DocumentTracking.Identification.ID, "-", "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "FG-IR-yy-\\d+", a.DocumentTracking.Identification.ID)
		}
		t, err := time.Parse("06", strings.TrimPrefix(ss[2], "0"))
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "FG-IR-yy-\\d+", a.DocumentTracking.Identification.ID)
		}

		if err := util.Write(filepath.Join(options.dir, t.Format("2006"), fmt.Sprintf("%s.json", a.DocumentTracking.Identification.ID)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, t.Format("2006"), fmt.Sprintf("%s.json", a.DocumentTracking.Identification.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
