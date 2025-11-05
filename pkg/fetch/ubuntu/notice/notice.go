package notice

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://ubuntu.com/security/notices.json?limit=%d&offset=%d&order=oldest&show_hidden=true"

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "ubuntu", "notice"),
		retry:       10,
		concurrency: 10,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Ubuntu Notices")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	header := make(http.Header)
	header.Set("Accept", "application/json")

	req, err := utilhttp.NewRequest(http.MethodGet, fmt.Sprintf(options.baseURL, 1, 0), utilhttp.WithRequestHeader(header))
	if err != nil {
		return errors.Wrap(err, "new request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "fetch notices")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return errors.Wrap(err, "decode json")
	}

	var reqs []*retryablehttp.Request
	for i := 0; i < r.TotalResults; i += 20 {
		req, err := utilhttp.NewRequest(http.MethodGet, fmt.Sprintf(options.baseURL, 20, i), utilhttp.WithRequestHeader(header))
		if err != nil {
			return errors.Wrap(err, "new request")
		}
		reqs = append(reqs, req)
	}

	if err := client.PipelineDo(reqs, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var r response
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, n := range r.Notices {
			switch {
			case strings.HasPrefix(n.ID, "USN"), strings.HasPrefix(n.ID, "LSN"), strings.HasPrefix(n.ID, "SSN"):
				splitted, err := util.Split(n.ID, "-", "-")
				if err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "(USN|LSN|SSN)-\\d{1,5}-\\d{1,2}", n.ID)
				}

				if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", n.ID)), n); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", n.ID)))
				}
			default:
				splitted, err := util.Split(n.ID, "-")
				if err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "\\d{1,5}-\\d{1,2}", n.ID)
				}

				if err := util.Write(filepath.Join(options.dir, "UNKNWON", splitted[0], fmt.Sprintf("%s.json", n.ID)), n); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "UNKNWON", splitted[0], fmt.Sprintf("%s.json", n.ID)))
				}
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline do")
	}

	return nil
}
