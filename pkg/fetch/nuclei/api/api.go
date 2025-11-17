package api

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://api.projectdiscovery.io/v1/template/"

type options struct {
	baseURL string
	dir     string
	retry   int
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

func Fetch(apikey string, opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "nuclei", "api"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Nuclei Public & Early Templates from API")
	if err := options.fetch(apikey); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (o options) fetch(apikey string) error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(o.retry))

	header := make(http.Header)
	header.Set("X-API-Key", apikey)

	for _, templateType := range []string{"public", "early"} {
		u, err := url.Parse(o.baseURL)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		u = u.JoinPath(templateType)

		for i := 0; ; i++ {
			q := make(url.Values)
			q.Set("offset", fmt.Sprintf("%d", i*100))
			q.Set("limit", "100")
			u.RawQuery = q.Encode()

			req, err := utilhttp.NewRequest(http.MethodGet, u.String(), utilhttp.WithRequestHeader(header))
			if err != nil {
				return errors.Wrap(err, "new request")
			}

			resp, err := client.Do(req)
			if err != nil {
				return errors.Wrap(err, "fetch nuclei api")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var r response
			if err := json.UnmarshalRead(resp.Body, &r); err != nil {
				return errors.Wrap(err, "decode json")
			}

			for _, r := range r.Results {
				p := filepath.Join(append(append([]string{o.dir}, strings.Split(r.Dir, "/")...), fmt.Sprintf("%s.json", r.ID))...)
				if err := util.Write(p, r); err != nil {
					return errors.Wrapf(err, "write %s", p)
				}
			}

			if len(r.Results) == 0 {
				break
			}
		}
	}

	return nil
}
