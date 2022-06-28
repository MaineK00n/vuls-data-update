package msf

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
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
		dir:     filepath.Join(util.SourceDir(), "msf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch Metasploit Framework")
	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch msf data")
	}

	ms := map[string]module{}
	if err := json.Unmarshal(bs, &ms); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	parseDateFn := func(layout string, v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse(layout, v); err == nil {
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	modules := make([]Module, 0, len(ms))
	for _, m := range ms {
		module := Module{
			Name:               m.Name,
			Fullname:           m.Fullname,
			Aliases:            m.Aliases,
			Rank:               m.Rank,
			DisclosureDate:     parseDateFn("2006-01-02", m.DisclosureDate),
			Type:               m.Type,
			Author:             m.Author,
			Description:        m.Description,
			References:         m.References,
			Platform:           m.Platform,
			Arch:               m.Arch,
			AutofilterPorts:    m.AutofilterPorts,
			AutofilterServices: m.AutofilterServices,
			Targets:            m.Targets,
			ModTime:            parseDateFn("2006-01-02 15:04:05 -0700", m.ModTime),
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
				log.Printf(`[WARN] failed to convert rport in %s. strconv.Atoi(%s) = %s`, m.Name, s, err)
			}
			module.Rport = &i
		case string:
			i, err := strconv.Atoi(v)
			if err != nil {
				log.Printf(`[WARN] failed to convert rport in %s. strconv.Atoi(%s) = %s`, m.Name, v, err)
			}
			module.Rport = &i
		case nil:
		default:
			log.Printf(`[WARN] unexpected rport type in %s. accepts: ["int", "float64", "string", "nil"], received: "%T"`, m.Name, v)
		}

		for k, note := range m.Notes {
			switch v := note.(type) {
			case string:
				module.Notes[k] = append(module.Notes[k], v)
			case []string:
				module.Notes[k] = append(module.Notes[k], v...)
			case []interface{}:
				for _, e := range v {
					s, ok := e.(string)
					if !ok {
						log.Printf(`[WARN] unexpected notes element type in %s. accepts: ["string"], received: "%T"`, m.Name, e)
						continue
					}
					module.Notes[k] = append(module.Notes[k], s)
				}
			default:
				log.Printf(`[WARN] unexpected notes type in %s. accepts: ["string", "[]string", "[]interface{}"], received: "%T"`, m.Name, v)
			}
		}

		switch v := m.SessionTypes.(type) {
		case []string:
			module.SessionTypes = v
		case []interface{}:
			for _, e := range v {
				s, ok := e.(string)
				if !ok {
					log.Printf(`[WARN] unexpected session_types element type in %s. accepts: ["string"], received: "%T"`, m.Name, e)
					continue
				}
				module.SessionTypes = append(module.SessionTypes, s)
			}
		case bool:
			if v {
				log.Printf(`[WARN] unexpected session_types value in %s. accepts: ["[]string", "[]interface{}", "bool(false)"], received: "true"`, m.Name)
			}
		default:
			log.Printf(`[WARN] unexpected session_types type in %s. accepts: ["[]string", "[]interface{}", "bool"], received: "%T"`, m.Name, v)
		}

		switch v := m.NeedsCleanup.(type) {
		case bool:
			module.NeedsCleanup = &v
		case nil:
		default:
			log.Printf(`[WARN] unexpected needs_cleanup type in %s. accepts: ["bool", "nil"], received: "%T"`, m.Name, v)
		}

		modules = append(modules, module)
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	bar := pb.StartNew(len(modules))
	for _, m := range modules {
		dir, file := filepath.Split(m.Fullname)

		if err := util.Write(filepath.Join(options.dir, dir, fmt.Sprintf("%s.json", file)), m); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, dir, fmt.Sprintf("%s.json", file)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
