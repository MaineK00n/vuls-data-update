package cvrf

import (
	"bufio"
	"encoding/xml"
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

const baseURL = "https://repo.openeuler.org/security/data/"

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "openeuler", "cvrf"),
		retry:       5,
		concurrency: 20,
		wait:        1 * time.Second,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	for _, kind := range []string{"cvrf", "hotpatch_cvrf"} {
		log.Printf("[INFO] Fetch openEuler %s Security Advisories (CVRF)", kind)
		is, err := options.fetchCVRFIndex(client, kind)
		if err != nil {
			return errors.Wrapf(err, "fetch %s index", kind)
		}
		if err := options.fetchCVRF(client, kind, is); err != nil {
			return errors.Wrapf(err, "fetch %s", kind)
		}
	}

	return nil
}

func (o options) fetchCVRFIndex(client *utilhttp.Client, kind string) ([]string, error) {
	u, err := url.JoinPath(o.baseURL, kind, "index.txt")
	if err != nil {
		return nil, errors.Wrap(err, "url join")
	}

	resp, err := client.Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var ls []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ls = append(ls, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "scanner encounter error")
	}

	return ls, nil
}

func (o options) fetchCVRF(client *utilhttp.Client, kind string, is []string) error {
	us := make([]string, 0, len(is))
	for _, i := range is {
		u, err := url.JoinPath(o.baseURL, kind, i)
		if err != nil {
			return errors.Wrap(err, "url join")
		}
		us = append(us, u)
	}

	if err := client.PipelineGet(us, o.concurrency, o.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var cvrf CVRF
		if err := xml.NewDecoder(resp.Body).Decode(&cvrf); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		splitted, err := util.Split(cvrf.DocumentTracking.Identification.ID, "-", "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "openEuler-(SA|HotPatchSA)-yyyy-\\d+", cvrf.DocumentTracking.Identification.ID)
		}

		if err := util.Write(filepath.Join(o.dir, splitted[1], splitted[2], fmt.Sprintf("%s.json", cvrf.DocumentTracking.Identification.ID)), cvrf); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, splitted[1], splitted[2], fmt.Sprintf("%s.json", cvrf.DocumentTracking.Identification.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
