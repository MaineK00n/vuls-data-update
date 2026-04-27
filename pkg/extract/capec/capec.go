package capec

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	fetchCapec "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/capec"
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
		dir: filepath.Join(util.CacheDir(), "extract", "mitre", "capec"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract MITRE CAPEC")

	// First pass: load attack-pattern files, build UUID→CAPEC-ID index
	attackPatternDir := filepath.Join(args, "attack-pattern")
	uuidToCapec := make(map[string]string)
	loaded := make(map[string]fetchCapec.Capec)
	readers := make(map[string]*utiljson.JSONReader)
	if _, err := os.Stat(attackPatternDir); err == nil {
		if err := filepath.WalkDir(attackPatternDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
			r := utiljson.NewJSONReader()
			var c fetchCapec.Capec
			if err := r.Read(path, args, &c); err != nil {
				return errors.Wrapf(err, "read json %s", path)
			}
			capecID := findExternalID(c.ExternalReferences, "capec")
			if capecID == "" {
				return nil
			}
			uuidToCapec[c.ID] = capecID
			loaded[capecID] = c
			readers[capecID] = r
			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", attackPatternDir)
		}
	}

	// Second pass: transform each CAPEC into normalized record
	for capecID, c := range loaded {
		extracted := convert(capecID, c, uuidToCapec, readers[capecID].Paths())
		outPath := filepath.Join(options.dir, "capec", fmt.Sprintf("%s.json", capecID))
		if err := util.Write(outPath, extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", outPath)
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.CAPEC,
		Name: new("MITRE Common Attack Pattern Enumeration and Classification (CAPEC)"),
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

func convert(id string, c fetchCapec.Capec, uuidToCapec map[string]string, raws []string) capecTypes.CAPEC {
	relatedCWEs := make([]string, 0)
	relatedAttacks := make([]string, 0)
	refs := make([]referenceTypes.Reference, 0)
	for _, r := range c.ExternalReferences {
		switch strings.ToLower(r.SourceName) {
		case "cwe":
			if r.ExternalID != nil && *r.ExternalID != "" {
				relatedCWEs = append(relatedCWEs, normalizeCWE(*r.ExternalID))
			}
		case "attack":
			if r.ExternalID != nil && *r.ExternalID != "" {
				relatedAttacks = append(relatedAttacks, *r.ExternalID)
			}
		case "capec":
			// self reference, skip
		default:
			url := ""
			if r.URL != nil {
				url = *r.URL
			}
			if url == "" {
				continue
			}
			refs = append(refs, referenceTypes.Reference{
				Source: r.SourceName,
				URL:    url,
			})
		}
	}

	desc := ""
	if c.Description != nil {
		desc = *c.Description
	}
	extDesc := ""
	if c.XCapecExtendedDescription != nil {
		extDesc = *c.XCapecExtendedDescription
	}
	name := ""
	if c.Name != nil {
		name = *c.Name
	}
	abstraction := ""
	if c.XCapecAbstraction != nil {
		abstraction = *c.XCapecAbstraction
	}
	status := ""
	if c.XCapecStatus != nil {
		status = *c.XCapecStatus
	}
	likelihood := ""
	if c.XCapecLikelihoodOfAttack != nil {
		likelihood = *c.XCapecLikelihoodOfAttack
	}
	severity := ""
	if c.XCapecTypicalSeverity != nil {
		severity = *c.XCapecTypicalSeverity
	}
	version := ""
	if c.XCapecVersion != nil {
		version = *c.XCapecVersion
	}
	skills := make(map[string]string)
	if c.XCapecSkillsRequired != nil {
		if c.XCapecSkillsRequired.High != nil {
			skills["High"] = *c.XCapecSkillsRequired.High
		}
		if c.XCapecSkillsRequired.Medium != nil {
			skills["Medium"] = *c.XCapecSkillsRequired.Medium
		}
		if c.XCapecSkillsRequired.Low != nil {
			skills["Low"] = *c.XCapecSkillsRequired.Low
		}
	}

	return capecTypes.CAPEC{
		ID:                  id,
		Name:                name,
		Description:         desc,
		ExtendedDescription: extDesc,
		Abstraction:         abstraction,
		Status:              status,
		LikelihoodOfAttack:  likelihood,
		TypicalSeverity:     severity,
		Domains:             append([]string(nil), c.XCapecDomains...),
		Prerequisites:       append([]string(nil), c.XCapecPrerequisites...),
		SkillsRequired:      skills,
		ResourcesRequired:   append([]string(nil), c.XCapecResourcesRequired...),
		Consequences:        cloneStringSliceMap(c.XCapecConsequences),
		RelatedCWEs:         relatedCWEs,
		RelatedAttacks:      relatedAttacks,
		ChildOf:             resolveUUIDs(c.XCapecChildOfRefs, uuidToCapec),
		ParentOf:            resolveUUIDs(c.XCapecParentOfRefs, uuidToCapec),
		CanFollow:           resolveUUIDs(c.XCapecCanFollowRefs, uuidToCapec),
		CanPrecede:          resolveUUIDs(c.XCapecCanPrecedeRefs, uuidToCapec),
		PeerOf:              resolveUUIDs(c.XCapecPeerOfRefs, uuidToCapec),
		AlternateTerms:      append([]string(nil), c.XCapecAlternateTerms...),
		Version:             version,
		Modified:            c.Modified,
		References:          refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.CAPEC,
			Raws: raws,
		},
	}
}

func findExternalID(refs []struct {
	Description *string `json:"description,omitempty"`
	ExternalID  *string `json:"external_id,omitempty"`
	SourceName  string  `json:"source_name"`
	URL         *string `json:"url,omitempty"`
}, sourceName string) string {
	for _, r := range refs {
		if strings.ToLower(r.SourceName) == sourceName && r.ExternalID != nil {
			return *r.ExternalID
		}
	}
	return ""
}

func normalizeCWE(raw string) string {
	if strings.HasPrefix(raw, "CWE-") {
		return raw
	}
	return "CWE-" + raw
}

func resolveUUIDs(uuids []string, index map[string]string) []string {
	out := make([]string, 0, len(uuids))
	for _, u := range uuids {
		if v, ok := index[u]; ok {
			out = append(out, v)
		}
	}
	return out
}

func cloneStringSliceMap(m map[string][]string) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

