package detail

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	jvnutil "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/util"
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
		dir:     filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "detail"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch JVNDB Detail")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(jvnutil.CheckRetry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "get checksum")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var cs []checksum
	if err := json.NewDecoder(resp.Body).Decode(&cs); err != nil {
		return errors.Wrap(err, "decode json")
	}

	var filtered []checksum
	for _, c := range cs {
		if strings.HasPrefix(c.Filename, "jvndb_detail_") {
			filtered = append(filtered, c)
		}
	}

	for _, c := range filtered {
		log.Printf("[INFO] Fetch JVNDB Detail Feed %s", c.Filename)
		vs, err := func() ([]Vulinfo, error) {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(c.URL)
			if err != nil {
				return nil, errors.Wrap(err, "fetch jvndb detail")
			}
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var feed feed
			if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
				return nil, errors.Wrap(err, "decode xml")
			}

			for _, v := range feed.Vulinfo {
				for i, item := range v.VulinfoData.Affected.AffectedItem {
					var vs []string
					for _, v := range item.VersionNumber {
						if v == "" {
							continue
						}
						vs = append(vs, v)
					}
					v.VulinfoData.Affected.AffectedItem[i].VersionNumber = vs
				}
			}

			return feed.Vulinfo, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		bar := pb.StartNew(len(vs))
		for _, a := range vs {
			splitted, err := util.Split(a.VulinfoID, "-", "-")
			if err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "JVNDB-yyyy-\\d{6}", a.VulinfoID)
				continue
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "JVNDB-yyyy-\\d{6}", a.VulinfoID)
				continue
			}

			if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.VulinfoID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.VulinfoID)))
			}

			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}
