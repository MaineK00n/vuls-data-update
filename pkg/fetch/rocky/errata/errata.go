package errata

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://apollo.build.resf.org/"

type options struct {
	baseURL string
	dir     string
	retry   int
	wait    time.Duration
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

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "rocky", "errata"),
		retry:   3,
		wait:    1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Rocky Linux Errata")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	bar := progressbar.Default(-1, "Paging Rocky Linux Errata")
	base, err := url.Parse(options.baseURL)
	if err != nil {
		return errors.Wrap(err, "parse base url")
	}
	next := "/api/v3/advisories/?page=1&size=100"
	for next != "" {
		if err := func() error {
			ref, err := url.Parse(next)
			if err != nil {
				return errors.Wrap(err, "join url path")
			}
			u := base.ResolveReference(ref)

			resp, err := client.Get(u.String())
			if err != nil {
				return errors.Wrap(err, "fetch advisory")
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				var a advisories
				if err := json.UnmarshalRead(resp.Body, &a); err != nil {
					return errors.Wrap(err, "decode json")
				}

				for _, a := range a.Advisories {
					splitted, err := util.Split(a.Name, "-", ":")
					if err != nil {
						return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(RLSA|RLBA|RLEA|RXSA)-yyyy:\\d{4,}", a.Name)
					}
					if _, err := time.Parse("2006", splitted[1]); err != nil {
						return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(RLSA|RLBA|RLEA|RXSA)-yyyy:\\d{4,}", a.Name)
					}

					if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.Name)), a); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.Name)))
					}
				}

				_ = bar.Add(len(a.Advisories))

				next = a.Links.Next

				return nil
			case http.StatusUnprocessableEntity:
				type validationError struct {
					Detail []struct {
						Loc  []any  `json:"loc"`
						Msg  string `json:"msg"`
						Type string `json:"type"`
					} `json:"detail"`
				}

				var e validationError
				if err := json.UnmarshalRead(resp.Body, &e); err != nil {
					return errors.Wrap(err, "decode json")
				}

				return errors.Errorf("validation error: %+v", e)
			default:
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			}
		}(); err != nil {
			return errors.Wrap(err, "fetch")
		}
		time.Sleep(options.wait)
	}
	_ = bar.Close()

	return nil
}
