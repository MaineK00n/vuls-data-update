package capec

import (
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"

	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	mitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec/mitigation"
	skillsrequiredTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec/skillsrequired"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	capec "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/capec"
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

// capecEntry collects everything we know about one attack-pattern: its
// CAPEC-ID, the parsed payload, a JSONReader that accumulates every raw
// file path contributing to it (attack-pattern + course-of-action +
// relationship), and the mitigations folded in via relationship.mitigates.
type capecEntry struct {
	capecID     string
	raw         capec.AttackPattern
	reader      *utiljson.JSONReader
	mitigations []mitigationTypes.Mitigation
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

	// Pass 1: walk attack-pattern/, build entries with their own readers.
	// Mitigations stay empty here; Pass 2 folds them in.
	entries := make(map[string]capecEntry)
	if err := walkJSON(filepath.Join(args, "attack-pattern"), func(path string) error {
		r := utiljson.NewJSONReader()
		var c capec.AttackPattern
		if err := r.Read(path, args, &c); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		capecID := func() string {
			for _, ref := range c.ExternalReferences {
				if ref.SourceName == "capec" && ref.ExternalID != nil {
					return *ref.ExternalID
				}
			}
			return ""
		}()
		if capecID == "" {
			return errors.Errorf("attack-pattern %s has no CAPEC external_reference", c.ID)
		}

		entries[c.ID] = capecEntry{capecID: capecID, raw: c, reader: r}

		return nil
	}); err != nil {
		return errors.Wrap(err, "load attack-patterns")
	}

	// Pass 2: walk relationship/ and fold each mitigation into its
	// target entry. Each relationship file is read twice:
	//  - once with a throwaway reader to identify the target attack-pattern,
	//  - then through that entry's own reader so both the relationship and
	//    course-of-action paths land in entry.reader.Paths() naturally.
	if err := walkJSON(filepath.Join(args, "relationship"), func(path string) error {
		var peek capec.Relationship
		if err := utiljson.NewJSONReader().Read(path, args, &peek); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}
		entry, ok := entries[peek.TargetRef]
		if !ok {
			return errors.Errorf("relationship %s: attack-pattern %s not in bundle", peek.ID, peek.TargetRef)
		}

		var rel capec.Relationship
		if err := entry.reader.Read(path, args, &rel); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}
		// As of the upstream CAPEC STIX 2.1 bundle, every relationship
		// is of type "mitigates" and links course-of-action --> attack-pattern.
		// Any deviation is a contract violation and should fail loudly.
		switch rel.RelationshipType {
		case "mitigates":
			if !strings.HasPrefix(rel.SourceRef, "course-of-action--") ||
				!strings.HasPrefix(rel.TargetRef, "attack-pattern--") {
				return errors.Errorf("unexpected mitigates source/target shape in %s: %s -> %s", rel.ID, rel.SourceRef, rel.TargetRef)
			}
			var coa capec.CourseOfAction
			if err := entry.reader.Read(filepath.Join(args, "course-of-action", fmt.Sprintf("%s.json", filepath.Base(rel.SourceRef))), args, &coa); err != nil {
				return errors.Wrapf(err, "read course-of-action %s", filepath.Join(args, "course-of-action", fmt.Sprintf("%s.json", filepath.Base(rel.SourceRef))))
			}
			entry.mitigations = append(entry.mitigations, mitigationTypes.Mitigation{
				Name: func() string {
					if coa.Name == nil {
						return ""
					}
					return *coa.Name
				}(),
				Description: func() string {
					if coa.Description == nil {
						return ""
					}
					return *coa.Description
				}(),
			})
			entries[peek.TargetRef] = entry
		default:
			return errors.Errorf("unexpected relationship_type %q in %s", rel.RelationshipType, rel.ID)
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "load relationships")
	}

	// Pass 3: transform each CAPEC entry into the normalized record
	for _, entry := range entries {
		extracted, err := convert(entry, entries)
		if err != nil {
			return errors.Wrapf(err, "convert %s", entry.capecID)
		}
		if err := util.Write(filepath.Join(options.dir, "capec", fmt.Sprintf("%s.json", entry.capecID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "capec", fmt.Sprintf("%s.json", entry.capecID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MitreCAPEC,
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

// walkJSON walks dir and invokes fn for every regular .json file inside
// it, skipping .git directories. Returns an error if dir does not exist —
// the caller is expected to point at a fetched CAPEC tree where all of
// attack-pattern/, course-of-action/, relationship/ are always present.
func walkJSON(dir string, fn func(path string) error) error {
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
		return fn(path)
	}); err != nil {
		return errors.Wrapf(err, "walk %s", dir)
	}
	return nil
}

func convert(e capecEntry, entries map[string]capecEntry) (capecTypes.CAPEC, error) {
	c := e.raw

	childOf, err := resolveCapecIDs(c.XCapecChildOfRefs, entries)
	if err != nil {
		return capecTypes.CAPEC{}, errors.Wrap(err, "resolve child_of")
	}
	parentOf, err := resolveCapecIDs(c.XCapecParentOfRefs, entries)
	if err != nil {
		return capecTypes.CAPEC{}, errors.Wrap(err, "resolve parent_of")
	}
	canFollow, err := resolveCapecIDs(c.XCapecCanFollowRefs, entries)
	if err != nil {
		return capecTypes.CAPEC{}, errors.Wrap(err, "resolve can_follow")
	}
	canPrecede, err := resolveCapecIDs(c.XCapecCanPrecedeRefs, entries)
	if err != nil {
		return capecTypes.CAPEC{}, errors.Wrap(err, "resolve can_precede")
	}
	peerOf, err := resolveCapecIDs(c.XCapecPeerOfRefs, entries)
	if err != nil {
		return capecTypes.CAPEC{}, errors.Wrap(err, "resolve peer_of")
	}

	relatedCWEs := make([]string, 0, len(c.ExternalReferences))
	relatedAttacks := make([]string, 0, len(c.ExternalReferences))
	refs := make([]referenceTypes.Reference, 0, len(c.ExternalReferences))
	for _, r := range c.ExternalReferences {
		switch strings.ToLower(r.SourceName) {
		case "cwe":
			if r.ExternalID != nil {
				relatedCWEs = append(relatedCWEs, *r.ExternalID)
			}
		case "attack":
			if r.ExternalID != nil {
				relatedAttacks = append(relatedAttacks, *r.ExternalID)
			}
		case "capec":
			// self reference: the CAPEC-ID is extracted at Pass 1; the
			// canonical capec.mitre.org URL is kept as a reference for
			// human-readable lookup.
			if r.URL != nil {
				refs = append(refs, referenceTypes.Reference{
					Source: "capec.mitre.org",
					URL:    *r.URL,
				})
			}
		default:
			if r.URL != nil {
				refs = append(refs, referenceTypes.Reference{
					Source: "capec.mitre.org",
					URL:    *r.URL,
				})
			}
		}
	}

	return capecTypes.CAPEC{
		ID: e.capecID,
		Name: func() string {
			if c.Name == nil {
				return ""
			}
			return *c.Name
		}(),
		Description: func() string {
			if c.Description == nil {
				return ""
			}
			return *c.Description
		}(),
		ExtendedDescription: func() string {
			if c.XCapecExtendedDescription == nil {
				return ""
			}
			return *c.XCapecExtendedDescription
		}(),
		Abstraction: func() string {
			if c.XCapecAbstraction == nil {
				return ""
			}
			return *c.XCapecAbstraction
		}(),
		Status: func() string {
			if c.XCapecStatus == nil {
				return ""
			}
			return *c.XCapecStatus
		}(),
		LikelihoodOfAttack: func() string {
			if c.XCapecLikelihoodOfAttack == nil {
				return ""
			}
			return *c.XCapecLikelihoodOfAttack
		}(),
		TypicalSeverity: func() string {
			if c.XCapecTypicalSeverity == nil {
				return ""
			}
			return *c.XCapecTypicalSeverity
		}(),
		Domains:       slices.Clone(c.XCapecDomains),
		Prerequisites: slices.Clone(c.XCapecPrerequisites),
		SkillsRequired: func() skillsrequiredTypes.SkillsRequired {
			if c.XCapecSkillsRequired == nil {
				return skillsrequiredTypes.SkillsRequired{}
			}
			var sr skillsrequiredTypes.SkillsRequired
			if c.XCapecSkillsRequired.High != nil {
				sr.High = *c.XCapecSkillsRequired.High
			}
			if c.XCapecSkillsRequired.Medium != nil {
				sr.Medium = *c.XCapecSkillsRequired.Medium
			}
			if c.XCapecSkillsRequired.Low != nil {
				sr.Low = *c.XCapecSkillsRequired.Low
			}
			return sr
		}(),
		ResourcesRequired: slices.Clone(c.XCapecResourcesRequired),
		Consequences:      maps.Clone(c.XCapecConsequences),
		ExampleInstances:  slices.Clone(c.XCapecExampleInstances),
		Mitigations:       e.mitigations,
		ExecutionFlow: func() string {
			if c.XCapecExecutionFlow == nil {
				return ""
			}
			return *c.XCapecExecutionFlow
		}(),
		RelatedCWEs:    relatedCWEs,
		RelatedAttacks: relatedAttacks,
		ChildOf:        childOf,
		ParentOf:       parentOf,
		CanFollow:      canFollow,
		CanPrecede:     canPrecede,
		PeerOf:         peerOf,
		AlternateTerms: slices.Clone(c.XCapecAlternateTerms),
		Version: func() string {
			if c.XCapecVersion == nil {
				return ""
			}
			return *c.XCapecVersion
		}(),
		Modified:   c.Modified,
		References: refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.MitreCAPEC,
			Raws: e.reader.Paths(),
		},
	}, nil
}

func resolveCapecIDs(uuids []string, entries map[string]capecEntry) ([]string, error) {
	out := make([]string, 0, len(uuids))
	for _, u := range uuids {
		e, ok := entries[u]
		if !ok {
			return nil, errors.Errorf("CAPEC reference UUID %s not in attack-pattern index", u)
		}
		out = append(out, e.capecID)
	}
	return out, nil
}
