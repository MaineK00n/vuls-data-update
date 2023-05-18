package netbsd

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://ftp.netbsd.org/pub/pkgsrc/distfiles/vulnerabilities"

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
		dir:     filepath.Join(util.SourceDir(), "netbsd"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch updateinfo data")
	}

	var vs []Vulnerability

	s := bufio.NewScanner(bytes.NewReader(bs))
	for s.Scan() {
		t := s.Text()
		if strings.HasPrefix(t, "#") {
			continue
		}

		ss := strings.Fields(t)
		if len(ss) != 3 {
			log.Printf(`[WARN]: unexpected line format. expected: "<package> <type of exploit> <URL>", actual: "%s"`, t)
			continue
		}
		vs = append(vs, Vulnerability{
			Package:       ss[0],
			TypeOfExploit: ss[1],
			URL:           ss[2],
		})
	}
	if err := s.Err(); err != nil {
		return errors.Wrap(err, "scanner encounter error")
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	if err := util.Write(filepath.Join(options.dir, "vulnerabilities.json.gz"), vs); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "vulnerabilities.json.gz"))
	}

	return nil
}
