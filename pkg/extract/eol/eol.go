package eol

import (
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	eolTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/eol"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

type options struct {
	eols map[string]map[string]map[string]eolTypes.EOL
	dir  string
}

type Option interface {
	apply(*options)
}

var defaultEOL = map[string]map[string]map[string]eolTypes.EOL{"os": os}

type eolOption map[string]map[string]map[string]eolTypes.EOL

func (e eolOption) apply(opts *options) {
	opts.eols = map[string]map[string]map[string]eolTypes.EOL(e)
}

func WithEOL(eol map[string]map[string]map[string]eolTypes.EOL) Option {
	return eolOption(eol)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

func Extract(opts ...Option) error {
	options := &options{
		eols: defaultEOL,
		dir:  filepath.Join(util.CacheDir(), "extract", "eol"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	maps.Keys(options.eols)

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract End of Life")
	now := time.Now().UTC()
	for c, eols := range options.eols {
		for e, m := range eols {
			for v, eol := range m {
				if !eol.Ended {
					ds := maps.Values(eol.Date)
					if len(ds) == 0 {
						continue
					}

					slices.SortFunc(ds, func(i, j time.Time) int {
						if (i).Before(j) {
							return -1
						}
						if (i).Equal(j) {
							return 0
						}
						return 1
					})
					if now.After(ds[len(ds)-1]) {
						eol.Ended = true
					}
				}
				m[v] = eol
			}

			if err := util.Write(filepath.Join(options.dir, "eol", c, fmt.Sprintf("%s.json", e)), m, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "eol", c, fmt.Sprintf("%s.json", e)))
			}
		}
	}

	return nil
}
