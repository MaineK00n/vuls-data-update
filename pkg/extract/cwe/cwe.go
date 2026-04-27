package cwe

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	fetchCWE "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/cwe"
)

type options struct {
	dir string
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

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "mitre", "cwe"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract MITRE CWE")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		kind := filepath.Base(filepath.Dir(path))
		switch kind {
		case "weakness":
			return extractWeakness(path, args, options.dir)
		case "category":
			return extractCategory(path, args, options.dir)
		case "view":
			return extractView(path, args, options.dir)
		default:
			return nil
		}
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.CWE,
		Name: new("MITRE Common Weakness Enumeration (CWE)"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{URL: u}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

func extractWeakness(path, args, outDir string) error {
	r := utiljson.NewJSONReader()
	var w fetchCWE.Weakness
	if err := r.Read(path, args, &w); err != nil {
		return errors.Wrapf(err, "read json %s", path)
	}

	id := normalizeID(w.ID)
	observedCVEs := make([]string, 0, len(w.ObservedExamples))
	for _, oe := range w.ObservedExamples {
		if strings.HasPrefix(oe.Reference, "CVE-") {
			observedCVEs = append(observedCVEs, oe.Reference)
		}
	}
	relatedAttack := make([]string, 0, len(w.RelatedAttackPatterns))
	for _, p := range w.RelatedAttackPatterns {
		if p == "" {
			continue
		}
		relatedAttack = append(relatedAttack, "CAPEC-"+p)
	}
	modes := make([]string, 0, len(w.ModesOfIntroduction))
	for _, m := range w.ModesOfIntroduction {
		if m.Phase != "" {
			modes = append(modes, m.Phase)
		}
	}
	platforms := collectPlatforms(w.ApplicablePlatforms)
	rws := make([]cweTypes.RelatedWeakness, 0, len(w.RelatedWeaknesses))
	for _, rw := range w.RelatedWeaknesses {
		rws = append(rws, cweTypes.RelatedWeakness{
			Nature: rw.Nature,
			CWEID:  normalizeID(rw.CWEID),
			ViewID: rw.ViewID,
		})
	}
	refs := extractReferences(w.References)

	extracted := cweTypes.CWE{
		ID:                    id,
		Kind:                  "weakness",
		Name:                  w.Name,
		Abstraction:           w.Abstraction,
		Structure:             w.Structure,
		Status:                w.Status,
		Description:           w.Description,
		ExtendedDescription:   w.ExtendedDescription,
		ModesOfIntroduction:   modes,
		LikelihoodOfExploit:   w.LikelihoodOfExploit,
		RelatedWeaknesses:     rws,
		RelatedAttackPatterns: relatedAttack,
		ObservedCVEs:          observedCVEs,
		Platforms:             platforms,
		References:            refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.CWE,
			Raws: r.Paths(),
		},
	}

	outPath := filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", id))
	if err := util.Write(outPath, extracted, true); err != nil {
		return errors.Wrapf(err, "write %s", outPath)
	}
	return nil
}

func extractCategory(path, args, outDir string) error {
	r := utiljson.NewJSONReader()
	var c fetchCWE.Category
	if err := r.Read(path, args, &c); err != nil {
		return errors.Wrapf(err, "read json %s", path)
	}

	id := normalizeID(c.ID)
	refs := extractReferences(c.References)
	extracted := cweTypes.CWE{
		ID:          id,
		Kind:        "category",
		Name:        c.Name,
		Status:      c.Status,
		Description: c.Summary,
		References:  refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.CWE,
			Raws: r.Paths(),
		},
	}

	outPath := filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", id))
	if err := util.Write(outPath, extracted, true); err != nil {
		return errors.Wrapf(err, "write %s", outPath)
	}
	return nil
}

func extractView(path, args, outDir string) error {
	r := utiljson.NewJSONReader()
	var v fetchCWE.View
	if err := r.Read(path, args, &v); err != nil {
		return errors.Wrapf(err, "read json %s", path)
	}

	id := normalizeID(v.ID)
	refs := extractReferences(v.References)
	extracted := cweTypes.CWE{
		ID:          id,
		Kind:        "view",
		Name:        v.Name,
		Status:      v.Status,
		Description: v.Objective,
		References:  refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.CWE,
			Raws: r.Paths(),
		},
	}

	outPath := filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", id))
	if err := util.Write(outPath, extracted, true); err != nil {
		return errors.Wrapf(err, "write %s", outPath)
	}
	return nil
}

func normalizeID(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "CWE-") {
		return raw
	}
	return "CWE-" + raw
}

func collectPlatforms(ap fetchCWE.ApplicablePlatforms) []string {
	var out []string
	for _, p := range ap.Language {
		if name := platformLabel(p); name != "" {
			out = append(out, "Language: "+name)
		}
	}
	for _, p := range ap.Technology {
		if name := platformLabel(p); name != "" {
			out = append(out, "Technology: "+name)
		}
	}
	for _, p := range ap.OperatingSystem {
		if name := platformLabel(p); name != "" {
			out = append(out, "OS: "+name)
		}
	}
	for _, p := range ap.Architecture {
		if name := platformLabel(p); name != "" {
			out = append(out, "Arch: "+name)
		}
	}
	return out
}

func platformLabel(p fetchCWE.ApplicablePlatform) string {
	switch {
	case p.Name != "":
		return p.Name
	case p.Class != "":
		return p.Class
	}
	return ""
}

func extractReferences(refs []fetchCWE.Reference) []referenceTypes.Reference {
	out := make([]referenceTypes.Reference, 0, len(refs))
	for _, r := range refs {
		if r.URL == "" {
			continue
		}
		source := r.Publisher
		if source == "" {
			source = r.Title
		}
		out = append(out, referenceTypes.Reference{
			Source: source,
			URL:    r.URL,
		})
	}
	return out
}

