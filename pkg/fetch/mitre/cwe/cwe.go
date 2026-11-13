package cwe

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/filepath"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

type options struct {
	dataURL string
	dir     string
	retry   int

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
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
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "cwe"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch MITRE Common Weakness Enumeration: CWE")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch cwe data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read all response body")
	}

	r, err := zip.NewReader(bytes.NewReader(bs), int64(len(bs)))
	if err != nil {
		return errors.Wrap(err, "read zip")
	}

	if len(r.File) != 1 {
		return errors.New("invalid CWE zip. too many files in archive")
	}

	f, err := r.File[0].Open()
	if err != nil {
		return errors.Wrap(err, "open file")
	}
	defer f.Close()

	var catalog weaknessCatalog
	if err := xml.NewDecoder(f).Decode(&catalog); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	exRefs := make(map[string]ExternalReference)
	for _, ref := range catalog.ExternalReferences {
		exRefs[ref.ReferenceID] = ref
	}

	slog.Info("Fetch CWE Weakness")
	weaknesses := convertWeaknesses(catalog.Weaknesses, exRefs)

	bar := progressbar.Default(int64(len(weaknesses)))
	for _, w := range weaknesses {
		p, err := utilfilepath.Join(options.dir, "weakness", fmt.Sprintf("%s.json", w.ID))
		if err != nil {
			return errors.Wrap(err, "join")
		}

		if err := util.Write(p, w); err != nil {
			return errors.Wrapf(err, "write %s", p)
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	slog.Info("Fetch CWE Category")
	categories := convertCategories(catalog.Categories, exRefs)

	bar = progressbar.Default(int64(len(categories)))
	for _, c := range categories {
		p, err := utilfilepath.Join(options.dir, "category", fmt.Sprintf("%s.json", c.ID))
		if err != nil {
			return errors.Wrap(err, "join")
		}

		if err := util.Write(p, c); err != nil {
			return errors.Wrapf(err, "write %s", p)
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	slog.Info("Fetch CWE View")
	views := convertViews(catalog.Views, exRefs)

	bar = progressbar.Default(int64(len(views)))
	for _, v := range views {
		p, err := utilfilepath.Join(options.dir, "view", fmt.Sprintf("%s.json", v.ID))
		if err != nil {
			return errors.Wrap(err, "join")
		}

		if err := util.Write(p, v); err != nil {
			return errors.Wrapf(err, "write %s", p)
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	// An empty output directory means the catalog no longer matches the
	// structure decoded above. Committing it would delete every file of that
	// kind from the raw repository, so fail instead.
	for _, kind := range []string{"weakness", "category", "view"} {
		d := filepath.Join(options.dir, kind)
		es, err := os.ReadDir(d)
		if err != nil {
			return errors.Wrapf(err, "read %s", d)
		}
		if len(es) == 0 {
			return errors.Errorf("no %s written to %s", kind, d)
		}
	}

	return nil
}

func convertWeaknesses(weaknesses []weakness, exRefs map[string]ExternalReference) []Weakness {
	converted := make([]Weakness, 0, len(weaknesses))
	for _, w := range weaknesses {
		backgroundDetails := make([]string, 0, len(w.BackgroundDetails))
		for _, d := range w.BackgroundDetails {
			backgroundDetails = append(backgroundDetails, d.Text)
		}

		modesOfIntroduction := make([]ModesOfIntroduction, 0, len(w.ModesOfIntroduction))
		for _, m := range w.ModesOfIntroduction {
			e := ModesOfIntroduction{
				Phase: m.Phase,
			}
			for _, n := range m.Note {
				e.Note = append(e.Note, n.Text)
			}
			modesOfIntroduction = append(modesOfIntroduction, e)
		}

		commonConsequences := make([]CommonConsequence, 0, len(w.CommonConsequences))
		for _, c := range w.CommonConsequences {
			commonConsequences = append(commonConsequences, CommonConsequence{
				Scope:      c.Scope,
				Impact:     c.Impact,
				Note:       c.Note.String(),
				Likelihood: c.Likelihood,
			})
		}

		potentialMitigations := make([]PotentialMitigation, 0, len(w.PotentialMitigations))
		for _, m := range w.PotentialMitigations {
			e := PotentialMitigation{
				MitigationID:       m.MitigationID,
				Phase:              m.Phase,
				Effectiveness:      m.Effectiveness,
				EffectivenessNotes: m.EffectivenessNotes.String(),
				Strategy:           m.Strategy,
			}
			for _, d := range m.Description {
				e.Description = append(e.Description, d.Text)
			}
			potentialMitigations = append(potentialMitigations, e)
		}

		observedExamples := make([]ObservedExample, 0, len(w.ObservedExamples))
		for _, e := range w.ObservedExamples {
			observedExamples = append(observedExamples, ObservedExample{
				Reference:   e.Reference,
				Description: e.Description.String(),
				Link:        e.Link,
			})
		}

		references := make([]Reference, 0, len(w.References))
		for _, ref := range w.References {
			exRef, ok := exRefs[ref.ExternalReferenceID]
			if !ok {
				slog.Warn("External_Reference not found", slog.String("external_reference_id", ref.ExternalReferenceID))
				continue
			}
			references = append(references, Reference{
				Section:           ref.Section,
				ExternalReference: exRef,
			})
		}

		contentHistory := ContentHistory{
			Submission: Submission{
				SubmissionName:         w.ContentHistory.Submission.SubmissionName,
				SubmissionOrganization: w.ContentHistory.Submission.SubmissionOrganization,
				SubmissionDate:         w.ContentHistory.Submission.SubmissionDate,
				SubmissionComment:      w.ContentHistory.Submission.SubmissionComment,
			},
		}
		for _, m := range w.ContentHistory.Modification {
			contentHistory.Modification = append(contentHistory.Modification, Modification{
				ModificationName:         m.ModificationName,
				ModificationOrganization: m.ModificationOrganization,
				ModificationDate:         m.ModificationDate,
				ModificationComment:      m.ModificationComment,
				ModificationImportance:   m.ModificationImportance,
			})
		}
		for _, n := range w.ContentHistory.PreviousEntryName {
			contentHistory.PreviousEntryName = append(contentHistory.PreviousEntryName, PreviousEntryName{
				Text: n.Text,
				Date: n.Date,
			})
		}
		for _, c := range w.ContentHistory.Contribution {
			contentHistory.Contribution = append(contentHistory.Contribution, Contribution{
				Type:                     c.Type,
				ContributionName:         c.ContributionName,
				ContributionOrganization: c.ContributionOrganization,
				ContributionDate:         c.ContributionDate,
				ContributionComment:      c.ContributionComment,
			})
		}

		alternateTerms := make([]AlternateTerm, 0, len(w.AlternateTerms))
		for _, t := range w.AlternateTerms {
			alternateTerms = append(alternateTerms, AlternateTerm{
				Term:        t.Term,
				Description: t.Description.Text,
			})
		}

		detectionMethods := make([]DetectionMethods, 0, len(w.DetectionMethods))
		for _, m := range w.DetectionMethods {
			detectionMethods = append(detectionMethods, DetectionMethods{
				DetectionMethodID:  m.DetectionMethodID,
				Method:             m.Method,
				Description:        m.Description.Text,
				Effectiveness:      m.Effectiveness,
				EffectivenessNotes: m.EffectivenessNotes.String(),
			})
		}

		relatedAttackPatterns := make([]string, 0, len(w.RelatedAttackPatterns))
		for _, p := range w.RelatedAttackPatterns {
			relatedAttackPatterns = append(relatedAttackPatterns, p.CAPECID)
		}

		converted = append(converted, Weakness{
			ID:                    w.ID,
			Name:                  w.Name,
			Abstraction:           w.Abstraction,
			Structure:             w.Structure,
			Status:                w.Status,
			Diagram:               w.Diagram,
			Description:           w.Description,
			ExtendedDescription:   w.ExtendedDescription.Text,
			RelatedWeaknesses:     w.RelatedWeaknesses,
			ApplicablePlatforms:   w.ApplicablePlatforms,
			BackgroundDetails:     backgroundDetails,
			ModesOfIntroduction:   modesOfIntroduction,
			LikelihoodOfExploit:   w.LikelihoodOfExploit,
			CommonConsequences:    commonConsequences,
			PotentialMitigations:  potentialMitigations,
			DemonstrativeExamples: w.DemonstrativeExamples,
			ObservedExamples:      observedExamples,
			References:            references,
			ContentHistory:        contentHistory,
			WeaknessOrdinalities:  w.WeaknessOrdinalities,
			AlternateTerms:        alternateTerms,
			DetectionMethods:      detectionMethods,
			TaxonomyMappings:      w.TaxonomyMappings,
			RelatedAttackPatterns: relatedAttackPatterns,
			Notes:                 w.Notes,
			AffectedResources:     w.AffectedResources,
			FunctionalAreas:       w.FunctionalAreas,
			MappingNotes:          convertMappingNotes(w.MappingNotes),
		})
	}
	return converted
}

func convertCategories(categories []category, exRefs map[string]ExternalReference) []Category {
	converted := make([]Category, 0, len(categories))
	for _, c := range categories {
		contentHistory := ContentHistory{
			Submission: Submission{
				SubmissionName:         c.ContentHistory.Submission.SubmissionName,
				SubmissionOrganization: c.ContentHistory.Submission.SubmissionOrganization,
				SubmissionDate:         c.ContentHistory.Submission.SubmissionDate,
				SubmissionComment:      c.ContentHistory.Submission.SubmissionComment,
			},
		}
		for _, m := range c.ContentHistory.Modification {
			contentHistory.Modification = append(contentHistory.Modification, Modification{
				ModificationName:         m.ModificationName,
				ModificationOrganization: m.ModificationOrganization,
				ModificationDate:         m.ModificationDate,
				ModificationComment:      m.ModificationComment,
				ModificationImportance:   m.ModificationImportance,
			})
		}
		for _, n := range c.ContentHistory.PreviousEntryName {
			contentHistory.PreviousEntryName = append(contentHistory.PreviousEntryName, PreviousEntryName{
				Text: n.Text,
				Date: n.Date,
			})
		}
		for _, contribution := range c.ContentHistory.Contribution {
			contentHistory.Contribution = append(contentHistory.Contribution, Contribution{
				Type:                     contribution.Type,
				ContributionName:         contribution.ContributionName,
				ContributionOrganization: contribution.ContributionOrganization,
				ContributionDate:         contribution.ContributionDate,
				ContributionComment:      contribution.ContributionComment,
			})
		}

		references := make([]Reference, 0, len(c.References))
		for _, ref := range c.References {
			exRef, ok := exRefs[ref.ExternalReferenceID]
			if !ok {
				slog.Warn("External_Reference not found", slog.String("external_reference_id", ref.ExternalReferenceID))
				continue
			}
			references = append(references, Reference{
				Section:           ref.Section,
				ExternalReference: exRef,
			})
		}

		converted = append(converted, Category{
			ID:               c.ID,
			Name:             c.Name,
			Status:           c.Status,
			Summary:          c.Summary.String(),
			ContentHistory:   contentHistory,
			Relationships:    c.Relationships,
			References:       references,
			Notes:            c.Notes,
			TaxonomyMappings: c.TaxonomyMappings,
			MappingNotes:     convertMappingNotes(c.MappingNotes),
		})
	}
	return converted
}

func convertViews(views []view, exRefs map[string]ExternalReference) []View {
	converted := make([]View, 0, len(views))
	for _, v := range views {
		contentHistory := ContentHistory{
			Submission: Submission{
				SubmissionName:         v.ContentHistory.Submission.SubmissionName,
				SubmissionOrganization: v.ContentHistory.Submission.SubmissionOrganization,
				SubmissionDate:         v.ContentHistory.Submission.SubmissionDate,
				SubmissionComment:      v.ContentHistory.Submission.SubmissionComment,
			},
		}
		for _, m := range v.ContentHistory.Modification {
			contentHistory.Modification = append(contentHistory.Modification, Modification{
				ModificationName:         m.ModificationName,
				ModificationOrganization: m.ModificationOrganization,
				ModificationDate:         m.ModificationDate,
				ModificationComment:      m.ModificationComment,
				ModificationImportance:   m.ModificationImportance,
			})
		}
		for _, n := range v.ContentHistory.PreviousEntryName {
			contentHistory.PreviousEntryName = append(contentHistory.PreviousEntryName, PreviousEntryName{
				Text: n.Text,
				Date: n.Date,
			})
		}
		for _, c := range v.ContentHistory.Contribution {
			contentHistory.Contribution = append(contentHistory.Contribution, Contribution{
				Type:                     c.Type,
				ContributionName:         c.ContributionName,
				ContributionOrganization: c.ContributionOrganization,
				ContributionDate:         c.ContributionDate,
				ContributionComment:      c.ContributionComment,
			})
		}

		references := make([]Reference, 0, len(v.References))
		for _, ref := range v.References {
			exRef, ok := exRefs[ref.ExternalReferenceID]
			if !ok {
				slog.Warn("External_Reference not found", slog.String("external_reference_id", ref.ExternalReferenceID))
				continue
			}
			references = append(references, Reference{
				Section:           ref.Section,
				ExternalReference: exRef,
			})
		}

		converted = append(converted, View{
			ID:             v.ID,
			Name:           v.Name,
			Type:           v.Type,
			Status:         v.Status,
			Objective:      v.Objective.String(),
			Audience:       v.Audience,
			Members:        v.Members,
			Notes:          v.Notes,
			ContentHistory: contentHistory,
			References:     references,
			Filter:         v.Filter,
			MappingNotes:   convertMappingNotes(v.MappingNotes),
		})
	}
	return converted
}

func convertMappingNotes(mn mappingNotes) MappingNotes {
	return MappingNotes{
		Usage:     mn.Usage,
		Rationale: mn.Rationale.String(),
		Comments:  mn.Comments.String(),
		Reasons: func() []Reason {
			var rs []Reason
			for _, r := range mn.Reasons {
				rs = append(rs, Reason{Type: r.Type})
			}
			return rs
		}(),
		Suggestions: func() []Suggestion {
			var ss []Suggestion
			for _, s := range mn.Suggestions {
				ss = append(ss, Suggestion{CWEID: s.CWEID, Comment: s.Comment})
			}
			return ss
		}(),
	}
}
