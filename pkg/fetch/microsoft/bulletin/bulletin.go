package bulletin

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"github.com/tealeg/xlsx"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

var dataURLs = []string{
	"https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
	"https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch2001-2008.xlsx",
}

type options struct {
	dataURLs []string
	dir      string
	retry    int
}

type Option interface {
	apply(*options)
}

type dataURLsOption []string

func (u dataURLsOption) apply(opts *options) {
	opts.dataURLs = u
}

func WithDataURLs(urls []string) Option {
	return dataURLsOption(urls)
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
		dataURLs: dataURLs,
		dir:      filepath.Join(util.CacheDir(), "fetch", "microsoft", "bulletin"),
		retry:    3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Windows Bulletin")

	bulletins := make(map[string][]Bulletin)
	for _, u := range options.dataURLs {
		if err := func() error {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return errors.Wrap(err, "fetch bulletin data")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			bs, err := io.ReadAll(resp.Body)
			if err != nil {
				return errors.Wrap(err, "read all response body")
			}

			f, err := xlsx.OpenBinary(bs)
			if err != nil {
				return errors.Wrap(err, "failed to open xlsx binary")
			}
			for _, sheet := range f.Sheets {
				for i, row := range sheet.Rows {
					// skip header
					if i == 0 {
						continue
					}

					var line Bulletin
					if err := row.ReadStruct(&line); err != nil {
						return errors.Wrap(err, "failed to read xlsx line")
					}

					if line.DatePosted == "" {
						continue
					}

					bulletins[line.BulletinID] = append(bulletins[line.BulletinID], line)
				}
			}

			return nil
		}(); err != nil {
			return errors.Wrap(err, "fetch")
		}
	}

	bar := progressbar.Default(int64(len(bulletins)))
	for bid, bs := range bulletins {
		splitted, err := util.Split(strings.TrimPrefix(strings.ToLower(bid), "ms"), "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "[mM][sS]yy-\\d{3}", bid)
		}
		if _, err := time.Parse("06", splitted[0]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "[mM][sS]yy-\\d{3}", bid)
		}

		if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", strings.ToUpper(bid))), bs); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", strings.ToUpper(bid))))
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
