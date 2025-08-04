package csaf

import (
	"archive/tar"
	"compress/bzip2"
	"encoding/json"
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

const baseURL = "https://ftp.suse.com/pub/projects/security/csaf.tar.bz2"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "suse", "csaf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch SUSE CSAF")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.baseURL)
	if err != nil {
		return errors.Wrap(err, "fetch suse csaf")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	tr := tar.NewReader(bzip2.NewReader(resp.Body))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var adv CSAF
		if err := json.NewDecoder(tr).Decode(&adv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		splitted, err := util.Split(adv.Document.Tracking.ID, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(SUSE|openSUSE)-(SU|RU|FU|OU)-.*", adv.Document.Tracking.ID)
		}

		y := "others"
		if lhs, _, ok := strings.Cut(splitted[2], ":"); ok {
			if _, err := time.Parse("2006", lhs); err == nil {
				y = lhs
			}
		}

		if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], y, fmt.Sprintf("%s.json", adv.Document.Tracking.ID)), adv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], y, fmt.Sprintf("%s.json", adv.Document.Tracking.ID)))
		}
	}

	return nil
}
