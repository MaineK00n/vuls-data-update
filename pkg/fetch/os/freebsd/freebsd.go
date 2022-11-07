package freebsd

import (
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://vuxml.freebsd.org/freebsd/vuln.xml.bz2"

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
		dir:            filepath.Join(util.SourceDir(), "freebsd"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch FreeBSD")
	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}

	var vuxml vuxml
	if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&vuxml); err != nil {
		return errors.Wrap(err, "decode advisory")
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

	advs := make([]Advisory, 0, len(vuxml.Vuln))
	for _, v := range vuxml.Vuln {
		if v.Cancelled != nil {
			advs = append(advs, Advisory{
				Vid: v.Vid,
				Cancelled: &Cancelled{
					Superseded: v.Cancelled.Superseded,
				},
			})
			continue
		}

		a := Advisory{
			Vid:         v.Vid,
			Topic:       v.Topic,
			Description: v.Description.Text,
			Dates: &Dates{
				Discovery: parseDateFn(v.Dates.Discovery),
				Entry:     parseDateFn(v.Dates.Entry),
				Modified:  parseDateFn(v.Dates.Modified),
			},
		}

		for _, p := range v.Affects {
			for _, n := range p.Name {
				a.Affects = append(a.Affects, Package{
					Name:  n,
					Range: p.Range,
				})
			}
		}

		for _, r := range v.References.URL {
			a.References = append(a.References, Reference{
				Source: "URL",
				Text:   r,
			})
		}

		for _, r := range v.References.Cvename {
			a.References = append(a.References, Reference{
				Source: "CVE",
				Text:   r,
			})
		}

		for _, r := range v.References.FreebsdSA {
			a.References = append(a.References, Reference{
				Source: "FreebsdSA",
				Text:   r,
			})
		}

		for _, r := range v.References.FreebsdPR {
			a.References = append(a.References, Reference{
				Source: "FreebsdPR",
				Text:   r,
			})
		}

		for _, r := range v.References.Mlist {
			source := "MLIST"
			if r.Msgid != "" {
				source = fmt.Sprintf("MLIST: %s", r.Msgid)
			}
			a.References = append(a.References, Reference{
				Source: source,
				Text:   r.Text,
			})
		}

		for _, r := range v.References.BID {
			a.References = append(a.References, Reference{
				Source: "BID",
				Text:   r,
			})
		}

		for _, r := range v.References.CertSA {
			a.References = append(a.References, Reference{
				Source: "CertSA",
				Text:   r,
			})
		}

		for _, r := range v.References.CertVU {
			a.References = append(a.References, Reference{
				Source: "CertVU",
				Text:   r,
			})
		}

		for _, r := range v.References.USCertSA {
			a.References = append(a.References, Reference{
				Source: "USCertSA",
				Text:   r,
			})
		}

		for _, r := range v.References.USCertTA {
			a.References = append(a.References, Reference{
				Source: "USCertTA",
				Text:   r,
			})
		}

		advs = append(advs, a)
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}
	if err := os.MkdirAll(options.dir, os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", options.dir)
	}

	bar := pb.StartNew(len(advs))
	for _, a := range advs {
		bs, err := json.Marshal(a)
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := util.Write(util.BuildFilePath(filepath.Join(options.dir, fmt.Sprintf("%s.json", a.Vid)), options.compressFormat), bs, options.compressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, a.Vid))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
