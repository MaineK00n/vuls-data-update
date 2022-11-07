package kev

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type options struct {
	dataURL        string
	dir            string
	retry          int
	compressFormat string
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		dataURL:        dataURL,
		dir:            filepath.Join(util.SourceDir(), "kev"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch Known Exploited Vulnerabilities Catalog")
	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch kev data")
	}

	var catalog catalog
	if err := json.Unmarshal(bs, &catalog); err != nil {
		return errors.Wrap(err, "json unmarshal")
	}

	parseDateFn := func(v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	vs := make([]Vulnerability, 0, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		vs = append(vs, Vulnerability{
			CveID:             v.CveID,
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			ShortDescription:  v.ShortDescription,
			RequiredAction:    v.RequiredAction,
			Notes:             v.Notes,
			DateAdded:         parseDateFn(v.DateAdded),
			DueDate:           parseDateFn(v.DueDate),
		})
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	bar := pb.StartNew(len(vs))
	for _, v := range vs {
		y := strings.Split(v.CveID, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			continue
		}

		bs, err := json.Marshal(v)
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := util.Write(util.BuildFilePath(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CveID)), options.compressFormat), bs, options.compressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, v.CveID))
		}

		bar.Increment()
	}
	bar.Finish()
	return nil
}
