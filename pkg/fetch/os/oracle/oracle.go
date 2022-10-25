package oracle

import (
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const advisoryURL = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"

type options struct {
	advisoryURL string
	dir         string
	retry       int
}

type Option interface {
	apply(*options)
}

type advisoryURLOption string

func (a advisoryURLOption) apply(opts *options) {
	opts.advisoryURL = string(a)
}

func WithAdvisoryURL(advisoryURL string) Option {
	return advisoryURLOption(advisoryURL)
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
		advisoryURL: advisoryURL,
		dir:         filepath.Join(util.SourceDir(), "oracle"),
		retry:       3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Oracle Linux")
	bs, err := util.FetchURL(options.advisoryURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}

	var root root
	if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
		return errors.Wrap(err, "unmarshal advisory")
	}

	tests, err := parseTests(root)
	if err != nil {
		return errors.Wrap(err, "parse rpminfo_test")
	}

	osDefs := parseDefinitions(root.Definitions.Definitions, tests)
	for v, defs := range osDefs {
		log.Printf("[INFO] Fetched Oracle Linux %s OVAL", v)
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

func parseTests(root root) (map[string]Package, error) {
	objs := parseObjects(root.Objects)
	states := parseStates(root.States)
	tests := map[string]Package{}
	for _, test := range root.Tests.RpminfoTest {
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
	for _, obj := range ovalObjs.RpminfoObject {
		objs[obj.ID] = obj.Name
	}
	return objs
}

func parseStates(objStates states) map[string]rpminfoState {
	states := map[string]rpminfoState{}
	for _, state := range objStates.RpminfoState {
		states[state.ID] = state
	}
	return states
}

func followTestRefs(test rpminfoTest, objects map[string]string, states map[string]rpminfoState) (Package, error) {
	var p Package

	if test.Object.ObjectRef == "" {
		return Package{}, errors.Errorf(`ObjectRef is empty. rpminfo_test id="%s"`, test.ID)
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return Package{}, errors.Errorf(`rpminfo_object not found. rpminfo_test id="%s", rpminfo_object id="%s"`, test.ID, test.Object.ObjectRef)
	}
	p.Name = pkgName

	if test.State.StateRef == "" {
		return p, nil
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return Package{}, errors.Errorf(`rpminfo_state not found. dpkginfo_test id="%s", dpkginfo_state id="%s"`, test.ID, test.State.StateRef)
	}

	if state.Evr.Datatype == "evr_string" && state.Evr.Operation == "less than" {
		p.FixedVersion = state.Evr.Text
	}

	if state.Arch.Operation == "pattern match" {
		p.Arch = state.Arch.Text
	}

	return p, nil
}

func parseDefinitions(ovalDefs []definition, tests map[string]Package) map[string][]Definition {
	defs := map[string][]Definition{}
	for _, d := range ovalDefs {
		var rs []Reference
		for _, r := range d.References {
			rs = append(rs, Reference{
				ID:     r.RefID,
				Source: r.Source,
				URL:    r.RefURL,
			})
		}

		var issued *time.Time
		t, err := time.Parse("2006-01-02", d.Advisory.Issued.Date)
		if err == nil {
			issued = &t
		} else {
			log.Printf(`[WARN] error time.Parse definition id="%s", date="%s", err="%s"`, d.ID, d.Advisory.Issued, err)
		}

		cves := make([]string, 0, len(d.Advisory.Cves))
		for _, c := range d.Advisory.Cves {
			cves = append(cves, c.Text)
		}

		osVer := strings.TrimPrefix(d.Affected.Platform, "Oracle Linux ")
		defs[osVer] = append(defs[osVer], Definition{
			DefinitionID: d.ID,
			Class:        d.Class,
			Title:        d.Title,
			Description:  d.Description,
			Affected: Affected{
				Family:   d.Affected.Family,
				Platform: d.Affected.Platform,
			},
			Advisory: Advisory{
				Severity: d.Advisory.Severity,
				Rights:   d.Advisory.Rights,
				Issued:   issued,
				Cves:     cves,
			},
			Packages:   walkCriterion(d.Criteria, tests),
			References: rs,
		})
	}
	return defs
}

func walkCriterion(cri criteria, tests map[string]Package) []Package {
	var pkgs []Package
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Oracle Linux ") && strings.HasSuffix(c.Comment, " is installed") {
			continue
		}

		if strings.HasPrefix(c.Comment, "Oracle Linux arch is ") {
			t, ok := tests[c.TestRef]
			if !ok {
				continue
			}

			for _, c := range cri.Criterias {
				for _, p := range walkCriterionPackage(c, tests) {
					pkgs = append(pkgs, Package{
						Name:         p.Name,
						FixedVersion: p.FixedVersion,
						Arch:         t.Arch,
					})
				}
			}
		}
	}

	for _, c := range cri.Criterias {
		if ps := walkCriterion(c, tests); len(ps) > 0 {
			pkgs = append(pkgs, ps...)
		}
	}

	return pkgs
}

func walkCriterionPackage(cri criteria, tests map[string]Package) []Package {
	var pkgs []Package
	for _, c := range cri.Criterions {
		t, ok := tests[c.TestRef]
		if !ok {
			continue
		}
		if strings.Contains(c.Comment, "is signed with the Oracle Linux") {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:         t.Name,
			FixedVersion: t.FixedVersion,
		})
	}

	for _, c := range cri.Criterias {
		if ps := walkCriterionPackage(c, tests); len(ps) > 0 {
			pkgs = append(pkgs, ps...)
		}
	}
	return pkgs
}
