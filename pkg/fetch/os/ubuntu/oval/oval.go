package oval

import (
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/codename"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const (
	mainURLFormat = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	subURLFormat  = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml.bz2"
)

type options struct {
	urls  map[string]string
	dir   string
	retry int
}

type Option interface {
	apply(*options)
}

type urlOption map[string]string

func (u urlOption) apply(opts *options) {
	opts.urls = u
}

func WithURLs(urls map[string]string) Option {
	return urlOption(urls)
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
		urls: map[string]string{
			"trusty":  fmt.Sprintf(mainURLFormat, "trusty"),
			"xenial":  fmt.Sprintf(mainURLFormat, "xenial"),
			"bionic":  fmt.Sprintf(mainURLFormat, "bionic"),
			"eoan":    fmt.Sprintf(subURLFormat, "eoan"),
			"focal":   fmt.Sprintf(mainURLFormat, "focal"),
			"groovy":  fmt.Sprintf(subURLFormat, "groovy"),
			"hirsute": fmt.Sprintf(mainURLFormat, "hirsute"),
			"impish":  fmt.Sprintf(mainURLFormat, "impish"),
			"jammy":   fmt.Sprintf(mainURLFormat, "jammy"),
			"kinetic": fmt.Sprintf(mainURLFormat, "kinetic"),
		},
		dir:   filepath.Join(util.SourceDir(), "ubuntu", "oval"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	for code, url := range options.urls {
		v, ok := codename.CodeToVer[code]
		if !ok {
			return errors.Errorf("unexpected codename. accepts %q, received %q", maps.Keys(codename.CodeToVer), code)
		}

		log.Printf("[INFO] Fetch Ubuntu %s", v)
		defs, err := options.fetchOVAL(url)
		if err != nil {
			return errors.Wrapf(err, "fetch ubuntu %s", v)
		}

		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", dir)
		}

		bar := pb.StartNew(len(defs))
		for _, def := range defs {
			if err := func() error {
				f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.json", def.DefinitionID)))
				if err != nil {
					return errors.Wrapf(err, "create %s", filepath.Join(dir, fmt.Sprintf("%s.json", def.DefinitionID)))
				}
				defer f.Close()

				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(def); err != nil {
					return errors.Wrap(err, "encode data")
				}
				return nil
			}(); err != nil {
				return err
			}

			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (opts options) fetchOVAL(url string) ([]Definition, error) {
	bs, err := util.FetchURL(url, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch oval")
	}

	var root root
	if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
		return nil, errors.Wrap(err, "unmarshal oval")
	}

	tests, err := parseTests(root)
	if err != nil {
		return nil, errors.Wrap(err, "parse dpkginfo_test")
	}

	return parseDefinitions(root.Definitions.Definitions, tests), nil
}

func parseTests(root root) (map[string]Package, error) {
	objs := parseObjects(root.Objects)
	states := parseStates(root.States)
	tests := map[string]Package{}
	for _, test := range root.Tests.DpkginfoTest {
		t, err := followTestRefs(test, objs, states)
		if err != nil {
			return nil, errors.Wrap(err, "follow test refs")
		}
		tests[test.ID] = t
	}
	return tests, nil
}

func parseObjects(ovalObjs objects) map[string]string {
	objs := map[string]string{}
	for _, obj := range ovalObjs.DpkginfoObject {
		ss := strings.Fields(obj.Comment)
		if len(ss) != 4 {
			log.Printf("[WARN] unexpected dpkginfo_object comment. expected: The '<SRC PKG NAME>' package binar(y|ies)., actual: %s", obj.Comment)
			continue
		}
		objs[obj.ID] = ss[1][1 : len(ss[1])-1]
	}
	return objs
}

func parseStates(objStates states) map[string]dpkginfoState {
	states := map[string]dpkginfoState{}
	for _, state := range objStates.DpkginfoState {
		states[state.ID] = state
	}
	return states
}

func followTestRefs(test dpkginfoTest, objects map[string]string, states map[string]dpkginfoState) (Package, error) {
	var p Package

	if test.Object.ObjectRef == "" {
		return Package{}, errors.Errorf(`ObjectRef is empty. dpkginfo_test id="%s"`, test.ID)
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return Package{}, errors.Errorf(`dpkginfo_object not found. dpkginfo_test id="%s", dpkginfo_object id="%s"`, test.ID, test.Object.ObjectRef)
	}
	p.Name = pkgName

	if test.State.StateRef == "" {
		return p, nil
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return Package{}, errors.Errorf(`dpkginfo_state not found. dpkginfo_test id="%s", dpkginfo_state id="%s"`, test.ID, test.State.StateRef)
	}

	if state.Evr.Datatype == "debian_evr_string" && state.Evr.Operation == "less than" {
		p.FixedVersion = state.Evr.Text
	}

	return p, nil
}

func parseDefinitions(ovalDefs []definition, tests map[string]Package) []Definition {
	var defs []Definition

	parseDateFn := func(v string) *time.Time {
		if v == "" || v == "unknown" {
			return nil
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return &t
		}
		if t, err := time.Parse("2006-01-02 15:04:05", v); err == nil {
			return &t
		}
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", v); err == nil {
			return &t
		}
		if t, err := time.Parse("2006-01-02 15:04:05 MST", v); err == nil {
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	for _, d := range ovalDefs {
		switch d.Class {
		case "inventory":
		case "vulnerability":
			def := Definition{
				DefinitionID: d.ID,
				Class:        d.Class,
				Title:        d.Title,
				Description:  d.Description,
				Note:         d.Note,
				Affected: Affected{
					Family:   d.Affected.Family,
					Platform: d.Affected.Platform,
				},
				Advisory: Advisory{
					Severity:        d.Advisory.Severity,
					PublicDate:      parseDateFn(d.Advisory.PublicDate),
					PublicDateAtUSN: parseDateFn(d.Advisory.PublicDateAtUSN),
					CRD:             parseDateFn(d.Advisory.CRD),
					AssignedTo:      d.Advisory.AssignedTo,
					DiscoveredBy:    d.Advisory.DiscoveredBy,
					Rights:          d.Advisory.Rights,
				},
				Packages: walkCriterion(d.Criteria, tests),
			}

			for _, r := range d.Advisory.Refs {
				def.Advisory.References = append(def.Advisory.References, r.URL)
			}

			for _, b := range d.Advisory.Bugs {
				def.Advisory.Bugzillas = append(def.Advisory.Bugzillas, b.URL)
			}

			for _, r := range d.References {
				def.References = append(def.References, Reference{
					ID:     r.RefID,
					Source: r.Source,
					URL:    r.RefURL,
				})
			}

			defs = append(defs, def)
		default:
			log.Printf("[WARN] unknown class: %s", d.Class)
		}
	}
	return defs
}

var notePattern = regexp.MustCompile(`^.*\(note: '(.*)'\)`)

func walkCriterion(cri criteria, tests map[string]Package) []Package {
	var pkgs []Package
	for _, c := range cri.Criterions {
		t, ok := tests[c.TestRef]
		if !ok {
			continue
		}

		var note string
		if m := notePattern.FindStringSubmatch(c.Comment); len(m) == 2 {
			note = m[1]
		}

		switch {
		case strings.Contains(c.Comment, "is related to the CVE in some way and has been fixed"):
			pkgs = append(pkgs, Package{
				Name:   t.Name,
				Status: "not-affected",
				Note:   note,
			})
		case strings.Contains(c.Comment, "while related to the CVE in some way, a decision has been made to ignore this issue"):
			pkgs = append(pkgs, Package{
				Name:   t.Name,
				Status: "ignored",
				Note:   note,
			})
		case strings.Contains(c.Comment, "is affected and may need fixing"):
			pkgs = append(pkgs, Package{
				Name:   t.Name,
				Status: "needs-triage",
				Note:   note,
			})
		case strings.Contains(c.Comment, "is affected and needs fixing"):
			pkgs = append(pkgs, Package{
				Name:   t.Name,
				Status: "needed",
				Note:   note,
			})
		case strings.Contains(c.Comment, "is affected, but a decision has been made to defer addressing it"):
			pkgs = append(pkgs, Package{
				Name:   t.Name,
				Status: "deferred",
				Note:   note,
			})
		case strings.Contains(c.Comment, "is affected. An update containing the fix has been completed and is pending publication"):
			pkgs = append(pkgs, Package{
				Name:   t.Name,
				Status: "pending",
				Note:   note,
			})
		case strings.Contains(c.Comment, "was vulnerable but has been fixed"):
			pkgs = append(pkgs, Package{
				Name:         t.Name,
				Status:       "released",
				FixedVersion: t.FixedVersion,
				Note:         note,
			})
		case strings.Contains(c.Comment, "was vulnerable and has been fixed, but no release version available for it."):
			pkgs = append(pkgs, Package{
				Name:   t.Name,
				Status: "released",
				Note:   note,
			})
		default:
			log.Printf("[WARN] failed to detect patch status. comment: %s", c.Comment)
		}
	}

	for _, c := range cri.Criterias {
		if ps := walkCriterion(c, tests); len(ps) > 0 {
			pkgs = append(pkgs, ps...)
		}
	}
	return pkgs
}
