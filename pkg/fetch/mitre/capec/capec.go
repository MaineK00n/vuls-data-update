package capec

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "capec"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch MITRE Common Attack Pattern Enumerations and Classifications: CAPEC")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch capec data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var bundle bundle
	if err := json.UnmarshalRead(resp.Body, &bundle); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar := progressbar.Default(int64(len(bundle.Objects)))
	for _, raw := range bundle.Objects {
		var head object
		if err := json.Unmarshal(raw, &head); err != nil {
			return errors.Wrap(err, "decode stix object envelope")
		}
		path := filepath.Join(options.dir, head.Type, fmt.Sprintf("%s.json", head.ID))
		switch head.Type {
		case "attack-pattern":
			var o AttackPattern
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(path, o); err != nil {
				return errors.Wrapf(err, "write %s", path)
			}
		case "course-of-action":
			var o CourseOfAction
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(path, o); err != nil {
				return errors.Wrapf(err, "write %s", path)
			}
		case "relationship":
			var o Relationship
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(path, o); err != nil {
				return errors.Wrapf(err, "write %s", path)
			}
		case "identity":
			var o Identity
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(path, o); err != nil {
				return errors.Wrapf(err, "write %s", path)
			}
		case "marking-definition":
			var o MarkingDefinition
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(path, o); err != nil {
				return errors.Wrapf(err, "write %s", path)
			}
		default:
			return errors.Errorf("unexpected STIX object type %q in %s", head.Type, head.ID)
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
