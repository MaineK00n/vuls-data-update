package osv

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://repo.openeuler.org/security/data/osv/"

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "openeuler", "osv"),
		retry:       3,
		concurrency: 5,
		wait:        1 * time.Second,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch openEuler Security Advisories (OSV)")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	ids, err := options.fetchList(client)
	if err != nil {
		return errors.Wrap(err, "fetch list")
	}
	if err := options.fetchOSV(client, ids); err != nil {
		return errors.Wrap(err, "fetch OSV")
	}
	return nil
}

func (o options) fetchList(client *utilhttp.Client) ([]string, error) {
	u, err := url.JoinPath(o.baseURL, "all.json")
	if err != nil {
		return nil, errors.Wrap(err, "join path")
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

	var list list
	if err := json.UnmarshalRead(resp.Body, &list); err != nil {
		return nil, errors.Wrap(err, "unmarshal json")
	}

	as := make([]string, len(list))
	for i, l := range list {
		as[i] = l.ID
	}
	return as, nil
}

func (o options) fetchOSV(client *utilhttp.Client, ids []string) error {
	us := make([]string, len(ids))
	for i, id := range ids {
		u, err := url.JoinPath(o.baseURL, fmt.Sprintf("%s.json", id))
		if err != nil {
			return errors.Wrapf(err, "join path for %s", id)
		}
		us[i] = u
	}

	if err := client.PipelineGet(us, o.concurrency, o.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var osv OSV
		if err := json.UnmarshalRead(resp.Body, &osv); err != nil {
			return errors.Wrap(err, "unmarshal json")
		}

		splitted, err := util.Split(osv.ID, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "OESA-yyyy-\\d+", osv.ID)
		}

		if err := util.Write(filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", osv.ID)), osv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", osv.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
