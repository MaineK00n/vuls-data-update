package cwe

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/pkg/errors"

	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	categoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/category"
	mappingnotesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes"
	reasonTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes/reason"
	suggestionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes/suggestion"
	memberTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/member"
	noteTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/note"
	taxonomymappingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/taxonomymapping"
	viewTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/view"
	audienceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/view/audience"
	weaknessTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness"
	alternatetermTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/alternateterm"
	applicableplatformTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/applicableplatform"
	commonconsequenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/commonconsequence"
	demonstrativeexampleTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/demonstrativeexample"
	detectionmethodTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/detectionmethod"
	modeofintroductionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/modeofintroduction"
	potentialmitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/potentialmitigation"
	relatedweaknessTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/relatedweakness"
	weaknessordinalityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/weaknessordinality"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	cwe "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/cwe"
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
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".json" {
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
			return errors.Errorf("unexpected kind %q in %s", kind, path)
		}
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MitreCWE,
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
	var w cwe.Weakness
	if err := r.Read(path, args, &w); err != nil {
		return errors.Wrapf(err, "read json %s", path)
	}

	extracted := cweTypes.CWE{
		ID:          fmt.Sprintf("CWE-%s", w.ID),
		Kind:        "weakness",
		Name:        w.Name,
		Status:      w.Status,
		Description: w.Description,
		Weakness: weaknessTypes.Weakness{
			Abstraction:         w.Abstraction,
			Structure:           w.Structure,
			Diagram:             w.Diagram,
			ExtendedDescription: w.ExtendedDescription,
			LikelihoodOfExploit: w.LikelihoodOfExploit,
			BackgroundDetails:   slices.Clone(w.BackgroundDetails),
			ModesOfIntroduction: func() []modeofintroductionTypes.ModeOfIntroduction {
				out := make([]modeofintroductionTypes.ModeOfIntroduction, 0, len(w.ModesOfIntroduction))
				for _, m := range w.ModesOfIntroduction {
					out = append(out, modeofintroductionTypes.ModeOfIntroduction{
						Phase: m.Phase,
						Notes: slices.Clone(m.Note),
					})
				}
				return out
			}(),
			RelatedWeaknesses: func() []relatedweaknessTypes.RelatedWeakness {
				out := make([]relatedweaknessTypes.RelatedWeakness, 0, len(w.RelatedWeaknesses))
				for _, rw := range w.RelatedWeaknesses {
					out = append(out, relatedweaknessTypes.RelatedWeakness{
						Nature:  rw.Nature,
						CWEID:   fmt.Sprintf("CWE-%s", rw.CWEID),
						ViewID:  fmt.Sprintf("CWE-%s", rw.ViewID),
						Ordinal: rw.Ordinal,
						ChainID: func() string {
							// Chain_ID is the only optional CWE-ID attribute on
							// Related_Weakness per the CWE XSD (cwe_schema_latest.xsd).
							if rw.ChainID == "" {
								return ""
							}
							return fmt.Sprintf("CWE-%s", rw.ChainID)
						}(),
					})
				}
				return out
			}(),
			RelatedAttackPatterns: func() []string {
				out := make([]string, 0, len(w.RelatedAttackPatterns))
				for _, p := range w.RelatedAttackPatterns {
					out = append(out, fmt.Sprintf("CAPEC-%s", p))
				}
				return out
			}(),
			AffectedResources: slices.Clone(w.AffectedResources),
			FunctionalAreas:   slices.Clone(w.FunctionalAreas),
			WeaknessOrdinalities: func() []weaknessordinalityTypes.WeaknessOrdinality {
				out := make([]weaknessordinalityTypes.WeaknessOrdinality, 0, len(w.WeaknessOrdinalities))
				for _, o := range w.WeaknessOrdinalities {
					out = append(out, weaknessordinalityTypes.WeaknessOrdinality{
						Ordinality:  o.Ordinality,
						Description: o.Description,
					})
				}
				return out
			}(),
			ApplicablePlatforms: func() []applicableplatformTypes.ApplicablePlatform {
				out := make([]applicableplatformTypes.ApplicablePlatform, 0, len(w.ApplicablePlatforms.Language)+len(w.ApplicablePlatforms.Technology)+len(w.ApplicablePlatforms.OperatingSystem)+len(w.ApplicablePlatforms.Architecture))
				for _, p := range w.ApplicablePlatforms.Language {
					out = append(out, applicableplatformTypes.ApplicablePlatform{Type: "language", Name: p.Name, Class: p.Class, Prevalence: p.Prevalence})
				}
				for _, p := range w.ApplicablePlatforms.Technology {
					out = append(out, applicableplatformTypes.ApplicablePlatform{Type: "technology", Name: p.Name, Class: p.Class, Prevalence: p.Prevalence})
				}
				for _, p := range w.ApplicablePlatforms.OperatingSystem {
					out = append(out, applicableplatformTypes.ApplicablePlatform{Type: "os", Name: p.Name, Class: p.Class, Prevalence: p.Prevalence})
				}
				for _, p := range w.ApplicablePlatforms.Architecture {
					out = append(out, applicableplatformTypes.ApplicablePlatform{Type: "architecture", Name: p.Name, Class: p.Class, Prevalence: p.Prevalence})
				}
				return out
			}(),
			AlternateTerms: func() []alternatetermTypes.AlternateTerm {
				out := make([]alternatetermTypes.AlternateTerm, 0, len(w.AlternateTerms))
				for _, t := range w.AlternateTerms {
					out = append(out, alternatetermTypes.AlternateTerm{
						Term:        t.Term,
						Description: t.Description,
					})
				}
				return out
			}(),
			CommonConsequences: func() []commonconsequenceTypes.CommonConsequence {
				out := make([]commonconsequenceTypes.CommonConsequence, 0, len(w.CommonConsequences))
				for _, c := range w.CommonConsequences {
					out = append(out, commonconsequenceTypes.CommonConsequence{
						Scope:      slices.Clone(c.Scope),
						Impact:     slices.Clone(c.Impact),
						Note:       c.Note,
						Likelihood: c.Likelihood,
					})
				}
				return out
			}(),
			PotentialMitigations: func() []potentialmitigationTypes.PotentialMitigation {
				out := make([]potentialmitigationTypes.PotentialMitigation, 0, len(w.PotentialMitigations))
				for _, m := range w.PotentialMitigations {
					out = append(out, potentialmitigationTypes.PotentialMitigation{
						MitigationID:       m.MitigationID,
						Phases:             slices.Clone(m.Phase),
						Descriptions:       slices.Clone(m.Description),
						Strategy:           m.Strategy,
						Effectiveness:      m.Effectiveness,
						EffectivenessNotes: m.EffectivenessNotes,
					})
				}
				return out
			}(),
			DemonstrativeExamples: func() []demonstrativeexampleTypes.DemonstrativeExample {
				out := make([]demonstrativeexampleTypes.DemonstrativeExample, 0, len(w.DemonstrativeExamples))
				for _, e := range w.DemonstrativeExamples {
					out = append(out, demonstrativeexampleTypes.DemonstrativeExample{
						DemonstrativeExampleID: e.DemonstrativeExampleID,
						Text:                   e.Text,
					})
				}
				return out
			}(),
			DetectionMethods: func() []detectionmethodTypes.DetectionMethod {
				out := make([]detectionmethodTypes.DetectionMethod, 0, len(w.DetectionMethods))
				for _, m := range w.DetectionMethods {
					out = append(out, detectionmethodTypes.DetectionMethod{
						DetectionMethodID:  m.DetectionMethodID,
						Method:             m.Method,
						Description:        m.Description,
						Effectiveness:      m.Effectiveness,
						EffectivenessNotes: m.EffectivenessNotes,
					})
				}
				return out
			}(),
			TaxonomyMappings: func() []taxonomymappingTypes.TaxonomyMapping {
				out := make([]taxonomymappingTypes.TaxonomyMapping, 0, len(w.TaxonomyMappings))
				for _, t := range w.TaxonomyMappings {
					out = append(out, taxonomymappingTypes.TaxonomyMapping{
						TaxonomyName: t.TaxonomyName,
						EntryID:      t.EntryID,
						EntryName:    t.EntryName,
						MappingFit:   t.MappingFit,
					})
				}
				return out
			}(),
			Notes:        collectNotes(w.Notes),
			MappingNotes: convertMappingNotes(w.MappingNotes),
		},
		References: extractReferences(w.References),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.MitreCWE,
			Raws: r.Paths(),
		},
	}

	if err := util.Write(filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", extracted.ID)))
	}
	return nil
}

func extractCategory(path, args, outDir string) error {
	r := utiljson.NewJSONReader()
	var c cwe.Category
	if err := r.Read(path, args, &c); err != nil {
		return errors.Wrapf(err, "read json %s", path)
	}

	extracted := cweTypes.CWE{
		ID:          fmt.Sprintf("CWE-%s", c.ID),
		Kind:        "category",
		Name:        c.Name,
		Status:      c.Status,
		Description: c.Summary,
		Category: categoryTypes.Category{
			Members: func() []memberTypes.Member {
				out := make([]memberTypes.Member, 0, len(c.Relationships))
				for _, m := range c.Relationships {
					out = append(out, memberTypes.Member{
						CWEID:  fmt.Sprintf("CWE-%s", m.CWEID),
						ViewID: fmt.Sprintf("CWE-%s", m.ViewID),
					})
				}
				return out
			}(),
			TaxonomyMappings: func() []taxonomymappingTypes.TaxonomyMapping {
				out := make([]taxonomymappingTypes.TaxonomyMapping, 0, len(c.TaxonomyMappings))
				for _, t := range c.TaxonomyMappings {
					out = append(out, taxonomymappingTypes.TaxonomyMapping{
						TaxonomyName: t.TaxonomyName,
						EntryID:      t.EntryID,
						EntryName:    t.EntryName,
						MappingFit:   t.MappingFit,
					})
				}
				return out
			}(),
			Notes:        collectNotes(c.Notes),
			MappingNotes: convertMappingNotes(c.MappingNotes),
		},
		References: extractReferences(c.References),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.MitreCWE,
			Raws: r.Paths(),
		},
	}

	if err := util.Write(filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", extracted.ID)))
	}
	return nil
}

func extractView(path, args, outDir string) error {
	r := utiljson.NewJSONReader()
	var v cwe.View
	if err := r.Read(path, args, &v); err != nil {
		return errors.Wrapf(err, "read json %s", path)
	}

	extracted := cweTypes.CWE{
		ID:          fmt.Sprintf("CWE-%s", v.ID),
		Kind:        "view",
		Name:        v.Name,
		Status:      v.Status,
		Description: v.Objective,
		View: viewTypes.View{
			Type: v.Type,
			Audience: func() []audienceTypes.Audience {
				out := make([]audienceTypes.Audience, 0, len(v.Audience))
				for _, a := range v.Audience {
					out = append(out, audienceTypes.Audience{
						Type:        a.Type,
						Description: a.Description,
					})
				}
				return out
			}(),
			Members: func() []memberTypes.Member {
				out := make([]memberTypes.Member, 0, len(v.Members))
				for _, m := range v.Members {
					out = append(out, memberTypes.Member{
						CWEID:  fmt.Sprintf("CWE-%s", m.CWEID),
						ViewID: fmt.Sprintf("CWE-%s", m.ViewID),
					})
				}
				return out
			}(),
			Notes:        collectNotes(v.Notes),
			MappingNotes: convertMappingNotes(v.MappingNotes),
		},
		References: extractReferences(v.References),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.MitreCWE,
			Raws: r.Paths(),
		},
	}

	if err := util.Write(filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(outDir, "cwe", fmt.Sprintf("%s.json", extracted.ID)))
	}
	return nil
}

func extractReferences(refs []cwe.Reference) []referenceTypes.Reference {
	out := make([]referenceTypes.Reference, 0, len(refs))
	for _, r := range refs {
		if r.URL == "" {
			continue
		}
		out = append(out, referenceTypes.Reference{
			Source: "cwe.mitre.org",
			URL:    r.URL,
		})
	}
	return out
}

func collectNotes(ns []cwe.Note) []noteTypes.Note {
	out := make([]noteTypes.Note, 0, len(ns))
	for _, n := range ns {
		out = append(out, noteTypes.Note{
			Type: n.Type,
			Text: n.Text,
		})
	}
	return out
}

func convertMappingNotes(m cwe.MappingNotes) mappingnotesTypes.MappingNotes {
	return mappingnotesTypes.MappingNotes{
		Usage:     m.Usage,
		Rationale: m.Rationale,
		Comments:  m.Comments,
		Reasons: func() []reasonTypes.Reason {
			// keep nil when empty so the outer MappingNotes stays zero
			// and the parent's omitzero strips the whole block
			var out []reasonTypes.Reason
			for _, r := range m.Reasons {
				out = append(out, reasonTypes.Reason{Type: r.Type})
			}
			return out
		}(),
		Suggestions: func() []suggestionTypes.Suggestion {
			var out []suggestionTypes.Suggestion
			for _, s := range m.Suggestions {
				out = append(out, suggestionTypes.Suggestion{
					CWEID:   fmt.Sprintf("CWE-%s", s.CWEID),
					Comment: s.Comment,
				})
			}
			return out
		}(),
	}
}
