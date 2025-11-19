package attack

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://raw.githubusercontent.com/mitre/cti/master"

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

func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "attack"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch MITRE ATT&CK Enterprise")
	if err := func() error {
		u, err := url.JoinPath(options.baseURL, "enterprise-attack/enterprise-attack.json")
		if err != nil {
			return errors.Wrap(err, "join url path")
		}

		resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
		if err != nil {
			return errors.Wrap(err, "fetch")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var enterprise enterprise
		if err := json.UnmarshalRead(resp.Body, &enterprise); err != nil {
			return errors.Wrap(err, "decode json")
		}

		bar := progressbar.Default(int64(len(enterprise.Objects)))
		for _, o := range enterprise.Objects {
			if err := util.Write(filepath.Join(options.dir, "enterprise", o.Type, fmt.Sprintf("%s.json", o.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "enterprise", o.Type, fmt.Sprintf("%s.json", o.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		return nil
	}(); err != nil {
		return errors.Wrap(err, "fetch enterprise")
	}

	log.Printf("[INFO] Fetch MITRE ATT&CK ICS")
	if err := func() error {
		u, err := url.JoinPath(options.baseURL, "ics-attack/ics-attack.json")
		if err != nil {
			return errors.Wrap(err, "join url path")
		}

		resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
		if err != nil {
			return errors.Wrap(err, "fetch")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var ics ics
		if err := json.UnmarshalRead(resp.Body, &ics); err != nil {
			return errors.Wrap(err, "decode json")
		}

		bar := progressbar.Default(int64(len(ics.Objects)))
		for _, o := range ics.Objects {
			if err := util.Write(filepath.Join(options.dir, "ics", o.Type, fmt.Sprintf("%s.json", o.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "ics", o.Type, fmt.Sprintf("%s.json", o.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		return nil
	}(); err != nil {
		return errors.Wrap(err, "fetch ics")
	}

	log.Printf("[INFO] Fetch MITRE ATT&CK Mobile")
	if err := func() error {
		u, err := url.JoinPath(options.baseURL, "mobile-attack/mobile-attack.json")
		if err != nil {
			return errors.Wrap(err, "join url path")
		}

		resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
		if err != nil {
			return errors.Wrap(err, "fetch")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var mobile mobile
		if err := json.UnmarshalRead(resp.Body, &mobile); err != nil {
			return errors.Wrap(err, "decode json")
		}

		bar := progressbar.Default(int64(len(mobile.Objects)))
		for _, o := range mobile.Objects {
			if err := util.Write(filepath.Join(options.dir, "mobile", o.Type, fmt.Sprintf("%s.json", o.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "mobile", o.Type, fmt.Sprintf("%s.json", o.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		return nil
	}(); err != nil {
		return errors.Wrap(err, "fetch mobile")
	}

	return nil
}
