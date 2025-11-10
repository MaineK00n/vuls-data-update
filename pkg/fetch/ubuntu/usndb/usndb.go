package usndb

import (
	"compress/bzip2"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://usn.ubuntu.com/usn-db/database-all.json.bz2"

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "ubuntu", "usndb"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Ubuntu USN DB")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch usndb data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var db map[string]USN
	if err := json.NewDecoder(bzip2.NewReader(resp.Body)).Decode(&db); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar := progressbar.Default(int64(len(db)))
	for _, usn := range db {
		s := int64(usn.Timestamp)
		t := time.Unix(s, int64(usn.Timestamp-float64(s))*1e9)

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", usn.ID)), usn); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", usn.ID)))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
