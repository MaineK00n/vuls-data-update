package snort

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "snort"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Snort Rules")
	rules, err := options.fetch()
	if err != nil {
		return errors.Wrap(err, "fetch snort rules")
	}

	bar := pb.StartNew(len(rules))
	for _, r := range rules {
		if err := util.Write(filepath.Join(options.dir, r.GID, r.SID, fmt.Sprintf("%s.json", r.Rev)), r); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, r.GID, r.SID, fmt.Sprintf("%s.json", r.Rev)))
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (opts options) fetch() ([]Rule, error) {
	var rules []Rule

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch file")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		switch filepath.Base(hdr.Name) {
		case "snort3-community.rules":
			re := regexp.MustCompile(`(?P<header>.+) \((?P<option>.+)\)`)
			sid := 1000000

			s := bufio.NewScanner(tr)
			for s.Scan() {
				match := re.FindStringSubmatch(s.Text())
				if len(match) == 0 {
					continue
				}

				r := Rule{
					GID:    "1",
					Rev:    "1",
					Header: match[re.SubexpIndex("header")],
					Option: strings.TrimSpace(match[re.SubexpIndex("option")]),
				}
				for _, op := range strings.Split(r.Option, ";") {
					lhs, rhs, _ := strings.Cut(strings.TrimSpace(op), ":")
					switch lhs {
					case "gid":
						r.GID = strings.TrimSpace(rhs)
					case "sid":
						r.SID = strings.TrimSpace(rhs)
					case "rev":
						r.Rev = strings.TrimSpace(rhs)
					default:
					}
				}
				if r.SID == "" {
					r.SID = fmt.Sprintf("%d", sid)
					sid++
				}

				rules = append(rules, r)
			}
			if err := s.Err(); err != nil {
				return nil, errors.Wrap(err, "scanner encounter error")
			}
		default:
		}
	}

	return rules, nil
}
