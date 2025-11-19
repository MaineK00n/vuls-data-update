package cve

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

const baseURL = "https://packages.vmware.com/photon/photon_cve_metadata/"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "photon", "cve"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Photon CVE")

	versions, err := options.fetchVersions()
	if err != nil {
		return errors.Wrap(err, "fetch versions")
	}

	for _, v := range versions {
		if err := func() error {
			u, err := url.JoinPath(options.baseURL, fmt.Sprintf("cve_data_photon%s.json", v))
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

			var cs []cve
			if err := json.UnmarshalRead(resp.Body, &cs); err != nil {
				return errors.Wrap(err, "decode json")
			}

			for _, c := range cs {
				switch {
				case strings.HasPrefix(c.CVEID, "CVE-"), strings.HasPrefix(c.CVEID, "BDSA-"):
					splitted, err := util.Split(c.CVEID, "-", "-")
					if err != nil {
						return errors.Errorf("unexpected ID format. expected: %q, actual: %q", []string{"CVE-yyyy-\\d{4,}", "BDSA-yyyy-\\d{4,}"}, c.CVEID)
					}

					if err := util.Write(filepath.Join(options.dir, v, c.Pkg, splitted[1], fmt.Sprintf("%s.json", c.CVEID)), c); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, c.Pkg, splitted[1], fmt.Sprintf("%s.json", c.CVEID)))
					}
				case strings.HasPrefix(c.CVEID, "UNK-"), c.CVEID == "Re":
					if err := util.Write(filepath.Join(options.dir, v, c.Pkg, "Others", fmt.Sprintf("%s.json", c.CVEID)), c); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, c.Pkg, "Others", fmt.Sprintf("%s.json", c.CVEID)))
					}
				default:
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", []string{"CVE-yyyy-\\d{4,}", "BDSA-yyyy-\\d{4,}", "UNK-\\d+", "Re"}, c.CVEID)
				}
			}

			return nil
		}(); err != nil {
			return errors.Wrapf(err, "fetch photon %s", v)
		}
	}
	return nil
}

func (opts options) fetchVersions() ([]string, error) {
	u, err := url.JoinPath(opts.baseURL, "photon_versions.json")
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return nil, errors.Wrap(err, "fetch")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var vs versions
	if err := json.UnmarshalRead(resp.Body, &vs); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	return vs.Branches, nil
}
