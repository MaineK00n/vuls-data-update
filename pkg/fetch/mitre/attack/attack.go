package attack

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://raw.githubusercontent.com/mitre/cti/master"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "attack"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	for _, domain := range []string{"enterprise", "ics", "mobile"} {
		slog.Info(fmt.Sprintf("Fetch MITRE ATT&CK %s", domain))
		if err := fetchDomain(options, domain); err != nil {
			return errors.Wrapf(err, "fetch %s", domain)
		}
	}

	return nil
}

func fetchDomain(opts *options, domain string) error {
	u, err := url.JoinPath(opts.baseURL, fmt.Sprintf("%s-attack/%s-attack.json", domain, domain))
	if err != nil {
		return errors.Wrap(err, "join url path")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return errors.Wrap(err, "fetch")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var b bundle
	if err := json.UnmarshalRead(resp.Body, &b); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar := progressbar.Default(int64(len(b.Objects)))
	for _, raw := range b.Objects {
		var head object
		if err := json.Unmarshal(raw, &head); err != nil {
			return errors.Wrap(err, "decode stix object envelope")
		}
		switch head.Type {
		case "attack-pattern":
			var o AttackPattern
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "campaign":
			var o Campaign
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "course-of-action":
			var o CourseOfAction
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "intrusion-set":
			var o IntrusionSet
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "malware":
			var o Malware
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "tool":
			var o Tool
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "relationship":
			var o Relationship
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-tactic":
			var o XMitreTactic
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "identity":
			var o Identity
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "marking-definition":
			var o MarkingDefinition
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-analytic":
			var o XMitreAnalytic
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-asset":
			var o XMitreAsset
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-collection":
			var o XMitreCollection
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-data-component":
			var o XMitreDataComponent
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-data-source":
			var o XMitreDataSource
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-detection-strategy":
			var o XMitreDetectionStrategy
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		case "x-mitre-matrix":
			var o XMitreMatrix
			if err := json.Unmarshal(raw, &o); err != nil {
				return errors.Wrapf(err, "decode %s %s", head.Type, head.ID)
			}
			if err := util.Write(filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)), o); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, domain, head.Type, fmt.Sprintf("%s.json", head.ID)))
			}
		default:
			return errors.Errorf("unexpected STIX object type %q in %s", head.Type, head.ID)
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
