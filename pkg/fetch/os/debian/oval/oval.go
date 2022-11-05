package oval

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian/codename"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const baseURL = "https://www.debian.org/security/oval/"

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
		dir:     filepath.Join(util.SourceDir(), "debian", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Debian OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		code := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml"), "oval-definitions-")
		v, ok := codename.CodeToVer[code]
		if !ok {
			return errors.Errorf("unexpected codename. accepts %q, received %q", maps.Keys(codename.CodeToVer), code)
		}

		log.Printf("[INFO] Fetch Debian %s OVAL", v)
		defs, err := options.fetchOVAL(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch debian %s oval", v)
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

func (opts options) walkIndexOf() ([]string, error) {
	bs, err := util.FetchURL(opts.baseURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var ovals []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "oval-definitions-") {
			return
		}
		ovals = append(ovals, txt)
	})
	return ovals, nil
}

func (opts options) fetchOVAL(ovalname string) ([]Definition, error) {
	u, err := url.JoinPath(opts.baseURL, ovalname)
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	bs, err := util.FetchURL(u, opts.retry)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", ovalname)
	}

	var root root
	if err := xml.Unmarshal(bs, &root); err != nil {
		return nil, errors.Wrapf(err, "unmarshal %s", ovalname)
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
		objs[obj.ID] = obj.Name
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
	for _, d := range ovalDefs {
		var rs []Reference
		for _, r := range d.References {
			rs = append(rs, Reference{
				ID:     r.RefID,
				Source: r.Source,
				URL:    r.RefURL,
			})
		}

		pkg := walkCriterion(d.Criteria, tests)

		var date *time.Time
		if d.Debian.Date != "" {
			t, err := time.Parse("2006-01-02", d.Debian.Date)
			if err == nil {
				date = &t
			} else {
				log.Printf(`[WARN] error time.Parse definition id="%s", date="%s", err="%s"`, d.ID, d.Debian.Date, err)
			}
		}

		defs = append(defs, Definition{
			DefinitionID: d.ID,
			Class:        d.Class,
			Title:        d.Title,
			Description:  d.Description,
			Debian: Debian{
				DSA:      d.Debian.DSA,
				MoreInfo: d.Debian.MoreInfo,
				Date:     date,
			},
			Affected: Affected{
				Family:   d.Affected.Family,
				Platform: d.Affected.Platform,
				Product:  d.Affected.Product,
			},
			Package:    *pkg,
			References: rs,
		})
	}
	return defs
}

func walkCriterion(cri criteria, tests map[string]Package) *Package {
	var pkg *Package
	for _, c := range cri.Criterions {
		t, ok := tests[c.TestRef]
		if ok {
			pkg = &t
			return pkg
		}
	}

	for _, c := range cri.Criterias {
		if pkg = walkCriterion(c, tests); pkg != nil {
			break
		}
	}
	return pkg
}
