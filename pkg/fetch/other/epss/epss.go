package epss

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
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

const dataURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

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
		dir:     filepath.Join(util.SourceDir(), "epss"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch Exploit Prediction Scoring System: EPSS")
	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch epss data")
	}

	gr, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return errors.Wrap(err, "read csv.gz")
	}
	defer gr.Close()

	var (
		model     string
		scoreDate *time.Time
		epsses    []EPSS
	)
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

		switch len(r) {
		case 2:
			if !strings.HasPrefix(r[0], "#model_version:") {
				log.Printf(`[WARN] unexpected model version. expected: "#model_version:<version>", actual: "%s"`, r[0])
				break
			}
			model = strings.TrimPrefix(r[0], "#model_version:")

			if !strings.HasPrefix(r[1], "score_date:") {
				log.Printf(`[WARN] unexpected score date. expected: "#score_date:<2006-01-02T15:04:05-0700>", actual: "%s"`, r[1])
				break
			}
			t, err := time.Parse("2006-01-02T15:04:05-0700", strings.TrimPrefix(r[1], "score_date:"))
			if err != nil {
				log.Printf(`[WARN] error time.Parse date="%s"`, strings.TrimPrefix(r[1], "score_date:"))
				break
			}
			scoreDate = &t
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
			epsses = append(epsses, EPSS{
				ID:         r[0],
				Model:      model,
				ScoreDate:  scoreDate,
				EPSS:       epss,
				Percentile: percentile,
			})
		default:
			log.Printf(`[WARN] unexpected epss line. expected: ["#model_version:<version>", "#score_date:<2006-01-02T15:04:05-0700>"] or ["<CVE ID>", "<EPSS Score>", "<EPSS Percentile>"], actual: %q`, r)
		}
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	bar := pb.StartNew(len(epsses))
	for _, e := range epsses {
		y := strings.Split(e.ID, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			continue
		}

		if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json.gz", e.ID)), e); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json.gz", e.ID)))
		}

		bar.Increment()
	}
	bar.Finish()
	return nil
}
