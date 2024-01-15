package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	epssTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/epss"
)

type options struct {
	dir         string
	concurrency int
	since       time.Time
	until       time.Time
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type sinceOption time.Time

func (t sinceOption) apply(opts *options) {
	opts.since = time.Time(t)
}

func WithSince(since time.Time) Option {
	return sinceOption(since)
}

type untilOption time.Time

func (t untilOption) apply(opts *options) {
	opts.until = time.Time(t)
}

func WithUntil(until time.Time) Option {
	return untilOption(until)
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "epss"),
		concurrency: runtime.NumCPU(),
		since:       time.Date(2021, time.April, 14, 0, 0, 0, 0, time.UTC),
		until:       time.Now(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Exploit Prediction Scoring System: EPSS")

	m := sync.Map{}
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		t, err := time.Parse("2006-01-02", strings.TrimSuffix(filepath.Base(path), ".json"))
		if err != nil {
			return errors.Wrapf(err, "parse %s", strings.TrimSuffix(filepath.Base(path), ".json"))
		}

		if t.Before(options.since) || t.After(options.until) {
			return nil
		}

		log.Printf("[INFO] Extract %s", path)

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var fetched epss.EPSS
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		t, err = time.Parse("2006-01-02T15:04:05-0700", fetched.ScoreDate)
		if err != nil {
			return errors.Wrapf(err, "parse %s", fetched.ScoreDate)
		}

		reqChan := make(chan epss.CVE, len(fetched.Data))
		go func() {
			defer close(reqChan)
			for _, d := range fetched.Data {
				m.Store(d.ID, struct{}{})
				reqChan <- d
			}
		}()

		bar := pb.StartNew(len(fetched.Data))
		g, ctx := errgroup.WithContext(context.Background())
		g.SetLimit(options.concurrency)
		for req := range reqChan {
			req := req
			g.Go(func() error {
				splitted, err := util.Split(req.ID, "-", "-")
				if err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", req.ID)
				}
				if _, err := time.Parse("2006", splitted[1]); err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", req.ID)
				}

				info := types.Info{
					ID: req.ID,
					Vulnerabilities: []types.Vulnerability{
						{
							CVE: req.ID,
							EPSS: []epssTypes.EPSS{{
								Model:      fetched.Model,
								ScoreDate:  t,
								EPSS:       req.EPSS,
								Percentile: req.Percentile,
							}},
						},
					},
					DataSource: source.EPSS,
				}
				if _, err := os.Stat(filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req.ID))); err == nil {
					f, err := os.Open(filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req.ID)))
					if err != nil {
						return errors.Wrapf(err, "open %s", filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req.ID)))
					}
					defer f.Close()

					var i types.Info
					if err := json.NewDecoder(f).Decode(&i); err != nil {
						return errors.Wrapf(err, "decode %s", filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req.ID)))
					}

					i.Vulnerabilities[0].EPSS = append(i.Vulnerabilities[0].EPSS, epssTypes.EPSS{
						Model:      fetched.Model,
						ScoreDate:  t,
						EPSS:       req.EPSS,
						Percentile: req.Percentile,
					})

					info = i
				}

				if err := util.Write(filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req.ID)), info); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req.ID)))
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					bar.Increment()
					return nil
				}
			})
		}
		if err := g.Wait(); err != nil {
			return errors.Wrap(err, "err in goroutine")
		}
		bar.Finish()

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	var cves []string
	m.Range(func(key, _ any) bool {
		cves = append(cves, key.(string))
		return true
	})

	reqChan := make(chan string, len(cves))
	go func() {
		defer close(reqChan)
		for _, cve := range cves {
			reqChan <- cve
		}
	}()

	log.Printf("[INFO] Finish EPSS")

	bar := pb.StartNew(len(cves))
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(options.concurrency)
	for req := range reqChan {
		req := req
		g.Go(func() error {
			splitted, err := util.Split(req, "-", "-")
			if err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", req)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", req)
			}

			f, err := os.Open(filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req)))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req)))
			}
			defer f.Close()

			var info types.Info
			if err := json.NewDecoder(f).Decode(&info); err != nil {
				return errors.Wrapf(err, "decode %s", filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req)))
			}

			slices.SortFunc(info.Vulnerabilities[0].EPSS, func(a, b epssTypes.EPSS) int {
				if a.ScoreDate.Before(b.ScoreDate) {
					return -1
				}
				if a.ScoreDate.After(b.ScoreDate) {
					return +1
				}
				return 0
			})

			if err := util.Write(filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req)), info); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "main", splitted[1], fmt.Sprintf("%s.json", req)))
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				bar.Increment()
				return nil
			}
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	bar.Finish()

	return nil
}
