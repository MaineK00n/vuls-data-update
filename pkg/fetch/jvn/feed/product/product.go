package product

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://jvndb.jvn.jp/ja/feed/checksum.txt"

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
		dir:     filepath.Join(util.CacheDir(), "jvn", "feed", "product"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch JVNDB Product")
	bs, err := utilhttp.Get(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "get checksum")
	}

	var cs []checksum
	if err := json.Unmarshal(bs, &cs); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	var filtered []checksum
	for _, c := range cs {
		if strings.HasPrefix(c.Filename, "myjvn_product_") {
			filtered = append(filtered, c)
		}
	}

	slices.SortFunc(filtered, func(a, b checksum) int {
		at, aerr := time.Parse("2006/01/02 15:04:05", a.LastModified)
		bt, berr := time.Parse("2006/01/02 15:04:05", b.LastModified)
		if aerr != nil && berr != nil {
			return 0
		}
		if aerr != nil || at.Before(bt) {
			return -1
		}
		if berr != nil || at.After(bt) {
			return +1
		}
		return 0
	})

	log.Printf("[INFO] Fetch JVNDB Product Feed %s", filtered[len(filtered)-1].Filename)
	bs, err = utilhttp.Get(filtered[len(filtered)-1].URL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch jvndb product")
	}

	var feed feed
	if err := xml.Unmarshal(bs, &feed); err != nil {
		return errors.Wrap(err, "unmarshal xml")
	}

	var ps []Product
	for _, v := range feed.VendorInfo.Vendor {
		for _, p := range v.Product {
			ps = append(ps, Product{
				Vid:   v.Vid,
				Vname: v.Vname,
				VCpe:  v.Cpe,
				Pid:   p.Pid,
				Pname: p.Pname,
				PCpe:  p.Cpe,
			})
		}
	}

	bar := pb.StartNew(len(ps))
	for _, p := range ps {
		if err := util.Write(filepath.Join(options.dir, p.Vid, fmt.Sprintf("%s.json", p.Pid)), p); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, p.Vid, fmt.Sprintf("%s.json", p.Pid)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
