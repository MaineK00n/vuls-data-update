package kev

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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
		dir:     filepath.Join(util.CacheDir(), "kev"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Known Exploited Vulnerabilities Catalog")
	bs, err := utilhttp.Get(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch kev data")
	}

	var catalog catalog
	if err := json.Unmarshal(bs, &catalog); err != nil {
		return errors.Wrap(err, "json unmarshal")
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
			DateAdded:         v.DateAdded,
			DueDate:           v.DueDate,
		})
	}

	bar := pb.StartNew(len(vs))
	for _, v := range vs {
		y := strings.Split(v.CveID, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			continue
		}

		if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CveID)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CveID)))
		}

		bar.Increment()
	}
	bar.Finish()
	return nil
}
