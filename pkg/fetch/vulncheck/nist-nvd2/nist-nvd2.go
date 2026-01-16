package nistnvd2

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://api.vulncheck.com/v3/backup/nist-nvd2"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "vulncheck", "nist-nvd2"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch VulnCheck NVD++ (nist-nvd2)")

	if err := os.MkdirAll(options.dir, 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", options.dir)
	}
	if err := os.WriteFile(filepath.Join(options.dir, "README.md"), []byte(`## Repository of VulnCheck NVD++ (nist-nvd2) data accumulation

All the data in this repository are fetched from VulnCheck by its API.

- https://docs.vulncheck.com/
- https://docs.vulncheck.com/api
- https://docs.vulncheck.com/community/nist-nvd/attribution

**CAUTION**

When you use the data in this repository, you *MUST* comply with the terms and conditions of VulnCheck NVD++: https://docs.vulncheck.com/community/nist-nvd/attribution
Notably, you must show "prominent attribution" to show the data is from VulnCheck NVD++ to users.
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
		return errors.Wrap(err, "fetch vulncheck nvd++")
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

		if !strings.HasPrefix(zf.FileInfo().Name(), "nvdcve-2.0-") || !strings.HasSuffix(zf.FileInfo().Name(), ".json.gz") {
			continue
		}

		feed, err := func() (api20, error) {
			f, err := zf.Open()
			if err != nil {
				return api20{}, errors.Wrapf(err, "open %s", zf.Name)
			}
			defer f.Close()

			gr, err := gzip.NewReader(f)
			if err != nil {
				return api20{}, errors.Wrap(err, "create gzip reader")
			}
			defer gr.Close()

			var feed api20
			if err := json.UnmarshalRead(gr, &feed); err != nil {
				return api20{}, errors.Wrap(err, "decode json")
			}
			return feed, nil
		}()
		if err != nil {
			return errors.Wrapf(err, "read %s", zf.Name)
		}

		for _, v := range feed.Vulnerabilities {
			splitted, err := util.Split(v.CVE.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVE.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVE.ID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)), v.CVE); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)))
			}
		}
	}

	return nil
}

func fetchBackupURL(client *utilhttp.Client, baseURL, apiToken string) (string, error) {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))

	resp, err := client.Get(baseURL, utilhttp.WithRequestHeader(header))
	if err != nil {
		return "", errors.Wrap(err, "fetch vulncheck nist-nvd2 backup")
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
