package msf

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "msf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Metasploit Framework")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch msf data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var ms map[string]module
	if err := json.UnmarshalRead(resp.Body, &ms); err != nil {
		return errors.Wrap(err, "decode json")
	}

	modules := make([]Module, 0, len(ms))
	for _, m := range ms {
		module := Module{
			Name:               m.Name,
			Fullname:           m.Fullname,
			Aliases:            m.Aliases,
			Rank:               m.Rank,
			DisclosureDate:     m.DisclosureDate,
			Type:               m.Type,
			Author:             m.Author,
			Description:        m.Description,
			References:         m.References,
			Platform:           m.Platform,
			Arch:               m.Arch,
			AutofilterPorts:    m.AutofilterPorts,
			AutofilterServices: m.AutofilterServices,
			Targets:            m.Targets,
			ModTime:            m.ModTime,
			Path:               m.Path,
			IsInstallPath:      m.IsInstallPath,
			RefName:            m.RefName,
			Check:              m.Check,
			PostAuth:           m.PostAuth,
			DefaultCredential:  m.DefaultCredential,
			Notes:              map[string][]string{},
		}

		switch v := m.Rport.(type) {
		case int:
			module.Rport = &v
		case float64:
			s := fmt.Sprintf("%.0f", v)
			i, err := strconv.Atoi(s)
			if err != nil {
				slog.Warn("failed to convert rport", slog.String("name", m.Name), slog.String("value", s), slog.Any("err", err))
			}
			module.Rport = &i
		case string:
			i, err := strconv.Atoi(v)
			if err != nil {
				slog.Warn("failed to convert rport", slog.String("name", m.Name), slog.String("value", v), slog.Any("err", err))
			}
			module.Rport = &i
		case nil:
		default:
			slog.Warn("unexpected rport type", slog.String("name", m.Name), slog.String("expected", "int, float64, string, nil"), slog.String("actual", fmt.Sprintf("%T", v)))
		}

		for k, note := range m.Notes {
			switch v := note.(type) {
			case string:
				module.Notes[k] = append(module.Notes[k], v)
			case []string:
				module.Notes[k] = append(module.Notes[k], v...)
			case []any:
				for _, e := range v {
					s, ok := e.(string)
					if !ok {
						slog.Warn("unexpected notes element type", slog.String("name", m.Name), slog.String("expected", "string"), slog.String("actual", fmt.Sprintf("%T", e)))
						continue
					}
					module.Notes[k] = append(module.Notes[k], s)
				}
			default:
				slog.Warn("unexpected notes type", slog.String("name", m.Name), slog.String("expected", "string, []string, []any"), slog.String("actual", fmt.Sprintf("%T", v)))
			}
		}

		switch v := m.SessionTypes.(type) {
		case []string:
			module.SessionTypes = v
		case []any:
			for _, e := range v {
				s, ok := e.(string)
				if !ok {
					slog.Warn("unexpected session_types element type", slog.String("name", m.Name), slog.String("expected", "string"), slog.String("actual", fmt.Sprintf("%T", e)))
					continue
				}
				module.SessionTypes = append(module.SessionTypes, s)
			}
		case bool:
			if v {
				slog.Warn("unexpected session_types value", slog.String("name", m.Name))
			}
		default:
			slog.Warn("unexpected session_types type", slog.String("name", m.Name), slog.String("expected", "[]string, []any, bool"), slog.String("actual", fmt.Sprintf("%T", v)))
		}

		switch v := m.NeedsCleanup.(type) {
		case bool:
			module.NeedsCleanup = &v
		case nil:
		default:
			slog.Warn("unexpected needs_cleanup type", slog.String("name", m.Name), slog.String("expected", "bool, nil"), slog.String("actual", fmt.Sprintf("%T", v)))
		}

		modules = append(modules, module)
	}

	bar := progressbar.Default(int64(len(modules)))
	for _, m := range modules {
		dir, file := filepath.Split(m.Fullname)

		if err := util.Write(filepath.Join(options.dir, dir, fmt.Sprintf("%s.json", file)), m); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, dir, fmt.Sprintf("%s.json", file)))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
