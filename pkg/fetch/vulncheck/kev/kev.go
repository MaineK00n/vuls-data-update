package kev

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"

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

func Fetch(apiToken string, opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "vulncheck", "kev"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch VulnCheck KEV")

	if err := os.MkdirAll(options.dir, 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", options.dir)
	}
	if err := os.WriteFile(filepath.Join(options.dir, "README.md"), []byte(`## Repository of VulnCheck KEV data accumulation

All the data in this repository are fetched from VulnCheck by its API.

- https://docs.vulncheck.com/
- https://docs.vulncheck.com/api
- https://docs.vulncheck.com/community/vulncheck-kev/attribution

**CAUTION**

When you use the data in this repository, you *MUST* comply with the terms and conditions of VulnCheck KEV: https://docs.vulncheck.com/community/vulncheck-kev/attribution
Notably, you must show "prominent attribution" to show the data is from VulnCheck KEV to users.
`), 0666); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "README.md"))
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	u, err := fetchBackupURL(client, options.baseURL, apiToken)
	if err != nil {
		return errors.Wrap(err, "fetch backup url")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrap(err, "fetch vulncheck kev")
	}
	defer resp.Body.Close()

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read all response body")
	}

	r, err := zip.NewReader(bytes.NewReader(bs), int64(len(bs)))
	if err != nil {
		return errors.Wrap(err, "create zip reader")
	}

	for _, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}

		if zf.FileInfo().Name() != "vulncheck_known_exploited_vulnerabilities.json" {
			continue
		}

		ks, err := func() ([]VulnCheckKEV, error) {
			f, err := zf.Open()
			if err != nil {
				return nil, errors.Wrapf(err, "open %s", zf.Name)
			}
			defer f.Close()

			var ks []VulnCheckKEV
			if err := json.UnmarshalRead(f, &ks); err != nil {
				return nil, errors.Wrap(err, "decode json")
			}
			return ks, nil
		}()
		if err != nil {
			return errors.Wrapf(err, "read %s", zf.Name)
		}

		bar := progressbar.Default(int64(len(ks)))
		for _, k := range ks {
			if err := util.Write(filepath.Join(options.dir, k.DateAdded.Format("2006"), fmt.Sprintf("%x.json", md5.Sum([]byte(fmt.Sprintf("%s %q", k.Name, k.CVE))))), k); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, k.DateAdded.Format("2006"), fmt.Sprintf("%x.json", md5.Sum([]byte(fmt.Sprintf("%s %q", k.Name, k.CVE))))))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	return nil
}

func fetchBackupURL(client *utilhttp.Client, baseURL, apiToken string) (string, error) {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))

	resp, err := client.Get(baseURL, utilhttp.WithRequestHeader(header))
	if err != nil {
		return "", errors.Wrap(err, "fetch vulncheck kev backup")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r backupResponse
	if err := json.UnmarshalRead(resp.Body, &r); err != nil {
		return "", errors.Wrap(err, "decode json")
	}

	if len(r.Data) != 1 {
		return "", errors.Errorf("expected data length is 1. actual response: %+v", r)
	}

	return r.Data[0].URL, nil
}
