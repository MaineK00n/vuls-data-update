package epss

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://epss.cyentia.com/epss_scores-%s.csv.gz"

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

func Fetch(args []string, opts ...Option) error {
	options := &options{
		dataURL:     dataURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "epss"),
		retry:       3,
		concurrency: 4,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Exploit Prediction Scoring System: EPSS")

	urls := make([]string, 0, len(args))
	for _, arg := range args {
		t, err := time.Parse("2006-01-02", arg)
		if err != nil {
			return errors.Wrapf(err, "invalid arg format. expected: %q, actual: %q", "2006-01-02", arg)
		}
		if t.Before(time.Date(2021, time.April, 14, 0, 0, 0, 0, time.UTC)) {
			return errors.New("do not provide older data than 2021-04-14")
		}
		urls = append(urls, fmt.Sprintf(options.dataURL, arg))
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(urls, options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode == http.StatusNotFound && slices.Contains([]string{"2021-04-22", "2021-04-23", "2021-04-24", "2021-04-25", "2021-04-26", "2021-06-07", "2021-06-18", "2022-07-14", time.Now().UTC().Format("2006-01-02")}, strings.TrimSuffix(strings.TrimPrefix(path.Base(resp.Request.URL.Path), "epss_scores-"), ".csv.gz")) {
				log.Printf("[WARN] %s is not found", resp.Request.URL)
				return nil
			}
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		t, err := time.Parse("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(path.Base(resp.Request.URL.Path), "epss_scores-"), ".csv.gz"))
		if err != nil {
			return errors.Wrapf(err, "invalid arg format. expected: %q, actual: %q", "2006-01-02", strings.TrimSuffix(strings.TrimPrefix(path.Base(resp.Request.URL.Path), "epss_scores-"), ".csv.gz"))
		}

		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "read csv.gz")
		}
		defer gr.Close()

		var root EPSS
		cr := csv.NewReader(gr)
		for {
			r, err := cr.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				if !errors.Is(err, csv.ErrFieldCount) {
					return errors.Wrap(err, "read csv record")
				}
			}

			switch {
			case t.Before(time.Date(2021, time.April, 14, 0, 0, 0, 0, time.UTC)):
				return errors.New("do not provide older data than 2021-04-14")
			case t.Before(time.Date(2021, time.September, 1, 0, 0, 0, 0, time.UTC)):
				if !strings.HasPrefix(r[0], "CVE-") {
					root.ScoreDate = t.Format("2006-01-02T15:04:05-0700")

					break
				}
				epss, err := strconv.ParseFloat(r[1], 64)
				if err != nil {
					log.Printf(`[WARN] error parse EPSS Score. strconv.ParseFloat(%s, 64)`, r[1])
					break
				}

				root.Data = append(root.Data, CVE{
					ID:   r[0],
					EPSS: epss,
				})
			case t.Before(time.Date(2022, time.February, 4, 0, 0, 0, 0, time.UTC)):
				if !strings.HasPrefix(r[0], "CVE-") {
					root.ScoreDate = t.Format("2006-01-02T15:04:05-0700")

					break
				}
				epss, err := strconv.ParseFloat(r[1], 64)
				if err != nil {
					log.Printf(`[WARN] error parse EPSS Score. strconv.ParseFloat(%s, 64)`, r[1])
					break
				}
				percentile, err := strconv.ParseFloat(r[2], 64)
				if err != nil {
					log.Printf(`[WARN] error parse EPSS Percentile. strconv.ParseFloat(%s, 64)`, r[2])
					break
				}
				root.Data = append(root.Data, CVE{
					ID:         r[0],
					EPSS:       epss,
					Percentile: &percentile,
				})
			case t.Before(time.Date(2023, time.March, 7, 0, 0, 0, 0, time.UTC)):
				switch len(r) {
				case 2:
					if !strings.HasPrefix(r[0], "#model_version:") {
						log.Printf(`[WARN] unexpected model version. expected: "#model_version:<version>", actual: "%s"`, r[0])
						break
					}
					root.Model = strings.TrimPrefix(r[0], "#model_version:")

					if !strings.HasPrefix(r[1], "score_date:") {
						log.Printf(`[WARN] unexpected score date. expected: "#score_date:<2006-01-02T15:04:05-0700>", actual: "%s"`, r[1])
						break
					}
					root.ScoreDate = strings.TrimPrefix(r[1], "score_date:")
				case 3:
					if !strings.HasPrefix(r[0], "CVE-") {
						break
					}
					epss, err := strconv.ParseFloat(r[1], 64)
					if err != nil {
						log.Printf(`[WARN] error parse EPSS Score. strconv.ParseFloat(%s, 64)`, r[1])
						break
					}
					percentile, err := strconv.ParseFloat(r[2], 64)
					if err != nil {
						log.Printf(`[WARN] error parse EPSS Percentile. strconv.ParseFloat(%s, 64)`, r[2])
						break
					}
					root.Data = append(root.Data, CVE{
						ID:         r[0],
						EPSS:       epss,
						Percentile: &percentile,
					})
				default:
					log.Printf(`[WARN] unexpected epss line. expected: ["#model_version:<version>", "#score_date:<2006-01-02T15:04:05-0700>"] or ["<CVE ID>", "<EPSS Score>", "<EPSS Percentile>"], actual: %q`, r)
				}
			default:
				switch len(r) {
				case 2:
					if !strings.HasPrefix(r[0], "#model_version:") {
						log.Printf(`[WARN] unexpected model version. expected: "#model_version:<version>", actual: "%s"`, r[0])
						break
					}
					root.Model = strings.TrimPrefix(r[0], "#model_version:")

					if !strings.HasPrefix(r[1], "score_date:") {
						log.Printf(`[WARN] unexpected score date. expected: "#score_date:<2006-01-02T15:04:05-0700>", actual: "%s"`, r[1])
						break
					}
					root.ScoreDate = strings.TrimPrefix(r[1], "score_date:")
				case 3:
					if !strings.HasPrefix(r[0], "CVE-") {
						break
					}
					epss, err := strconv.ParseFloat(r[1], 64)
					if err != nil {
						log.Printf(`[WARN] error parse EPSS Score. strconv.ParseFloat(%s, 64)`, r[1])
						break
					}
					percentile, err := strconv.ParseFloat(r[2], 64)
					if err != nil {
						log.Printf(`[WARN] error parse EPSS Percentile. strconv.ParseFloat(%s, 64)`, r[2])
						break
					}
					root.Data = append(root.Data, CVE{
						ID:         r[0],
						EPSS:       epss,
						Percentile: &percentile,
					})
				default:
					log.Printf(`[WARN] unexpected epss line. expected: ["#model_version:<version>", "#score_date:<2006-01-02T15:04:05-0700>"] or ["<CVE ID>", "<EPSS Score>", "<EPSS Percentile>"], actual: %q`, r)
				}
			}

		}

		if err := util.Write(filepath.Join(options.dir, t.Format("2006"), fmt.Sprintf("%s.json", t.Format("2006-01-02"))), root); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, t.Format("2006"), fmt.Sprintf("%s.json", t.Format("2006-01-02"))))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
