package attack

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	analyticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/analytic"
	assetTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/asset"
	campaignTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/campaign"
	datacomponentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/datacomponent"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/datasource"
	detectionstrategyTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/detectionstrategy"
	groupTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/group"
	mitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/mitigation"
	procedureTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/procedure"
	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
	softwareTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/software"
	tacticrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/tacticref"
	tacticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/tactic"
	techniqueTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/technique"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	stixdatasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	attack "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/attack"
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

// stixTypeToKind maps a STIX `type` discriminator to the ATT&CK Kind
// for the primary records the extractor keeps. Treating dispatch as
// data (vs. a 12-arm switch) lets discoverPrimaries reject any STIX
// type we haven't taught the extractor in one place.
var stixTypeToKind = map[string]attackTypes.Kind{
	"attack-pattern":             attackTypes.KindTechnique,
	"x-mitre-tactic":             attackTypes.KindTactic,
	"course-of-action":           attackTypes.KindMitigation,
	"intrusion-set":              attackTypes.KindGroup,
	"malware":                    attackTypes.KindSoftware,
	"tool":                       attackTypes.KindSoftware,
	"campaign":                   attackTypes.KindCampaign,
	"x-mitre-asset":              attackTypes.KindAsset,
	"x-mitre-detection-strategy": attackTypes.KindDetectStrategy,
	"x-mitre-analytic":           attackTypes.KindAnalytic,
	"x-mitre-data-source":        attackTypes.KindDataSource,
	"x-mitre-data-component":     attackTypes.KindDataComponent,
}

// stixTypesNotExtracted are STIX types intentionally skipped during
// discovery — bundle / provenance metadata and matrix layout objects
// that carry no per-record content the ATT&CK web UI surfaces from a
// single ID query.
var stixTypesNotExtracted = map[string]bool{
	"identity":           true,
	"marking-definition": true,
	"x-mitre-collection": true,
	"x-mitre-matrix":     true,
}

// entryInfo carries every per-ext-ID detail Stage 2 needs to build one
// canonical record. Stage 1 populates a single map[extID]*entryInfo
// instead of five parallel maps.
type entryInfo struct {
	kind     attackTypes.Kind
	stixType string
	peek     stixPeek // first-occurrence peek, used to project own cross-ref fields in Stage 2
	paths    []string // every bundle copy of this ext-ID's primary file
	files    []string // every file Stage 2 has to open: primary + cross-domain copies + relationship + cross-ref targets
}

// uuidInfo collapses the three UUID-keyed lookups Stage 1c does when
// resolving a relationship's src / tgt UUIDs. The zero value is a
// "not in the extract set" answer (ext == ""), matching the old
// missing-key semantics.
type uuidInfo struct {
	ext  string
	kind attackTypes.Kind
	path string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "mitre", "attack"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract MITRE ATT&CK")

	// Stage 1 builds the file list each ext-ID needs to produce its
	// canonical record (entries) plus the UUID lookup Stage 1c needs
	// to resolve relationships (uuids). The two Tactic shortname maps
	// stay separate because they're keyed by something other than
	// extID / UUID. Nothing else crosses the Stage 1 ↔ Stage 2
	// boundary.
	entries := make(map[string]*entryInfo)
	uuids := make(map[string]uuidInfo)
	tacticShortnameToID := make(map[string]string)
	tacticUUIDToShortname := make(map[string]string)

	// Stage 1a: walk every STIX file, peek the extended discriminator
	// envelope, apply the distribution-artifact filter, and register
	// the file under its ext-ID. Skipped types (relationship / identity
	// / marking-definition / ...) leave no trace; relationship files
	// are processed in Stage 1c.
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

		peek, err := peekPrimary(path)
		if err != nil {
			return errors.Wrapf(err, "peek %s", path)
		}
		// Relationships are handled in Stage 1c. The four
		// not-extracted STIX kinds simply leave no trace.
		if peek.Type == "relationship" || stixTypesNotExtracted[peek.Type] {
			return nil
		}
		kind, ok := stixTypeToKind[peek.Type]
		if !ok {
			return errors.Errorf("unexpected STIX type. expected: %q, actual: %q", knownStixTypes, peek.Type)
		}
		extID := externalID(peek.ExternalReferences, "mitre-attack")
		if extID == "" {
			return nil
		}
		// MITRE distributes referenced objects with every bundle that
		// needs them: T1047 (Enterprise-only) is mirrored into the
		// mobile/ and ics/ bundle dirs because those bundles reference
		// it from their relationships. Each copy declares its true
		// domain in x_mitre_domains, so we keep only files whose
		// bundle dir matches one of their declared domains; the rest
		// are distribution artifacts we drop here before any indexing.
		bundleDomain := bundleDomainOf(args, path)
		if !slices.Contains(peek.XMitreDomains, bundleDomain) {
			return nil
		}
		uuids[peek.ID] = uuidInfo{ext: extID, kind: kind, path: path}
		e, ok := entries[extID]
		if !ok {
			e = &entryInfo{kind: kind, stixType: peek.Type, peek: peek}
			entries[extID] = e
		}
		e.paths = append(e.paths, path)
		e.files = append(e.files, path)
		if kind == attackTypes.KindTactic && peek.XMitreShortname != nil && *peek.XMitreShortname != "" {
			tacticShortnameToID[*peek.XMitreShortname] = extID
			tacticUUIDToShortname[peek.ID] = *peek.XMitreShortname
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	// Stage 1b: per-extID, link the files Stage 2 will need to build
	// the cross-ref fields. Forward refs (e.g. Technique → Tactic via
	// TacticRefs / KillChainPhases) and reverse refs (Tactic →
	// Techniques) both surface as file membership in entries[id].files,
	// so Stage 2 doesn't need a global edge index to know which files
	// to open.
	for _, e := range entries {
		switch e.kind {
		case attackTypes.KindTechnique:
			// KillChainPhases name the Tactic by its shortname; resolve
			// to the Tactic's ext-ID so we can add the Technique to that
			// Tactic's file list (for Tactic.Techniques reverse).
			for _, kc := range e.peek.KillChainPhases {
				switch kc.KillChainName {
				case "mitre-attack", "mitre-ics-attack", "mitre-mobile-attack":
					if tacticExt, ok := tacticShortnameToID[kc.PhaseName]; ok {
						if tac, ok := entries[tacticExt]; ok {
							tac.files = append(tac.files, e.paths...)
						}
					}
				}
			}
			// TacticRefs point at Tactic UUIDs; pull the Tactic file in
			// for provenance + technique.Tactics ID resolution, and
			// pull the Technique's file into the Tactic for reverse.
			for _, tr := range e.peek.TacticRefs {
				u, ok := uuids[tr]
				if !ok {
					continue
				}
				tac, ok := entries[u.ext]
				if !ok {
					continue
				}
				e.files = append(e.files, tac.paths...)
				tac.files = append(tac.files, e.paths...)
			}
		case attackTypes.KindDetectStrategy:
			for _, ar := range e.peek.XMitreAnalyticRefs {
				u, ok := uuids[ar]
				if !ok {
					continue
				}
				an, ok := entries[u.ext]
				if !ok {
					continue
				}
				e.files = append(e.files, an.paths...)
				an.files = append(an.files, e.paths...)
			}
		case attackTypes.KindDataComponent:
			if e.peek.XMitreDataSourceRef == nil {
				continue
			}
			u, ok := uuids[*e.peek.XMitreDataSourceRef]
			if !ok {
				continue
			}
			ds, ok := entries[u.ext]
			if !ok {
				continue
			}
			e.files = append(e.files, ds.paths...)
			ds.files = append(ds.files, e.paths...)
		}
	}

	// Stage 1c: link relationship files into both sides' file lists,
	// plus every cross-domain copy of the other-side primary so Stage 2
	// can replay them for provenance without a global edge index.
	doms, err := os.ReadDir(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}
	for _, dom := range doms {
		if !dom.IsDir() || dom.Name() == ".git" {
			continue
		}
		relDir := filepath.Join(args, dom.Name(), "relationship")
		relFiles, err := os.ReadDir(relDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return errors.Wrapf(err, "read %s", relDir)
		}
		for _, f := range relFiles {
			if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
				continue
			}
			path := filepath.Join(relDir, f.Name())
			r, err := decodeRelationship(path)
			if err != nil {
				return errors.Wrapf(err, "relationship %s", path)
			}
			if r.RelationshipType == "" || r.SourceRef == "" || r.TargetRef == "" {
				continue
			}
			src := entries[uuids[r.SourceRef].ext]
			tgt := entries[uuids[r.TargetRef].ext]
			if src != nil {
				src.files = append(src.files, path)
				if tgt != nil {
					src.files = append(src.files, tgt.paths...)
				}
			}
			if tgt != nil {
				tgt.files = append(tgt.files, path)
				if src != nil {
					tgt.files = append(tgt.files, src.paths...)
				}
			}
		}
	}

	// Stage 2: for each unique ext-ID, walk its file list. Each file is
	// either this entry's primary (or a cross-domain copy of it), a
	// relationship file we parse for src/tgt direction + per-edge
	// content, or another primary's file pulled in by cross-ref. The
	// per-entry rels struct accumulates the kind-specific fields and
	// is then handed to convert() unchanged.
	for extID, e := range entries {
		kind := e.kind
		stixType := e.stixType
		ownPeek := e.peek
		files := e.files
		selfSet := make(map[string]bool, len(e.paths))
		for _, p := range e.paths {
			selfSet[p] = true
		}

		r := utiljson.NewJSONReader()
		var raw any
		domains := slices.Clone(ownPeek.XMitreDomains)
		domainSeen := make(map[string]bool, len(domains))
		for _, d := range domains {
			domainSeen[d] = true
		}

		// Per-kind accumulators. Only the slots for the entry's own
		// kind get populated below; every other field stays zero so the
		// final Attack struct literal sees just the natural defaults.
		var (
			techniqueParent              string
			techniqueSubtechniques       []string
			techniqueTacticShortnames    []string
			techniqueProcedures          []procedureTypes.Procedure
			techniqueMitigations         []relatedrefTypes.RelatedRef
			techniqueAssetsTargeted      []relatedrefTypes.RelatedRef
			techniqueDetectionStrategies []relatedrefTypes.RelatedRef

			mitigationTechniquesMitigated []relatedrefTypes.RelatedRef

			groupTechniquesUsed      []techniqueusedTypes.TechniqueUsed
			groupSoftwaresUsed       []relatedrefTypes.RelatedRef
			groupCampaignsAttributed []relatedrefTypes.RelatedRef

			softwareTechniquesUsed []techniqueusedTypes.TechniqueUsed
			softwareGroupsUsing    []relatedrefTypes.RelatedRef
			softwareCampaignsUsing []relatedrefTypes.RelatedRef

			campaignTechniquesUsed   []techniqueusedTypes.TechniqueUsed
			campaignGroupsAttributed []relatedrefTypes.RelatedRef
			campaignSoftwaresUsed    []relatedrefTypes.RelatedRef

			tacticTechniques []string

			assetTechniquesTargeting []relatedrefTypes.RelatedRef

			detStrategyAnalytics          []string
			detStrategyTechniquesDetected []relatedrefTypes.RelatedRef

			analyticDetectionStrategy string

			dataSourceComponents []string
			dataComponentSource  string
		)

		// Forward cross-refs come from the entry's own peek and never
		// need another file to be opened.
		switch kind {
		case attackTypes.KindTechnique:
			for _, kc := range ownPeek.KillChainPhases {
				switch kc.KillChainName {
				case "mitre-attack", "mitre-ics-attack", "mitre-mobile-attack":
					techniqueTacticShortnames = append(techniqueTacticShortnames, kc.PhaseName)
				}
			}
			for _, tr := range ownPeek.TacticRefs {
				if sn, ok := tacticUUIDToShortname[tr]; ok {
					techniqueTacticShortnames = append(techniqueTacticShortnames, sn)
				}
			}
		case attackTypes.KindDetectStrategy:
			for _, ar := range ownPeek.XMitreAnalyticRefs {
				if u, ok := uuids[ar]; ok {
					detStrategyAnalytics = append(detStrategyAnalytics, u.ext)
				}
			}
		case attackTypes.KindDataComponent:
			if ownPeek.XMitreDataSourceRef != nil {
				if u, ok := uuids[*ownPeek.XMitreDataSourceRef]; ok {
					dataComponentSource = u.ext
				}
			}
		}

		seenFile := make(map[string]bool, len(files))
		for _, path := range files {
			if seenFile[path] {
				continue
			}
			seenFile[path] = true

			if selfSet[path] {
				if raw == nil {
					rr, err := readConcrete(stixType, path, args, r)
					if err != nil {
						return err
					}
					raw = rr
					continue
				}
				if err := attachRead(stixType, path, args, r); err != nil {
					return errors.Wrapf(err, "attach self %s for %s", path, extID)
				}
				p, err := peekPrimary(path)
				if err != nil {
					return errors.Wrapf(err, "peek %s", path)
				}
				for _, d := range p.XMitreDomains {
					if !domainSeen[d] {
						domainSeen[d] = true
						domains = append(domains, d)
					}
				}
				continue
			}

			fp, err := peekPrimary(path)
			if err != nil {
				return errors.Wrapf(err, "peek %s", path)
			}
			if fp.Type == "relationship" {
				rel, err := decodeRelationship(path)
				if err != nil {
					return errors.Wrapf(err, "relationship %s", path)
				}
				if rel.RelationshipType == "" || rel.SourceRef == "" || rel.TargetRef == "" {
					continue
				}
				if err := attachRead("relationship", path, args, r); err != nil {
					return errors.Wrapf(err, "attach relationship %s for %s", path, extID)
				}
				srcU := uuids[rel.SourceRef]
				tgtU := uuids[rel.TargetRef]
				srcExt := srcU.ext
				tgtExt := tgtU.ext
				srcKind := srcU.kind
				tgtKind := tgtU.kind
				desc := ""
				if rel.Description != nil {
					desc = *rel.Description
				}
				refs := toReferences(rel.ExternalReferences)

				switch rel.RelationshipType {
				case "subtechnique-of":
					if kind != attackTypes.KindTechnique {
						break
					}
					if extID == srcExt && tgtExt != "" {
						techniqueParent = tgtExt
					}
					if extID == tgtExt && srcExt != "" {
						techniqueSubtechniques = append(techniqueSubtechniques, srcExt)
					}
				case "mitigates":
					if extID == srcExt && tgtExt != "" && kind == attackTypes.KindMitigation {
						mitigationTechniquesMitigated = append(mitigationTechniquesMitigated, relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
					}
					if extID == tgtExt && srcExt != "" && kind == attackTypes.KindTechnique {
						techniqueMitigations = append(techniqueMitigations, relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
					}
				case "uses":
					if srcExt == "" || tgtExt == "" {
						break
					}
					switch {
					case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindTechnique:
						if extID == srcExt && kind == attackTypes.KindGroup {
							groupTechniquesUsed = append(groupTechniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs})
						}
						if extID == tgtExt && kind == attackTypes.KindTechnique {
							techniqueProcedures = append(techniqueProcedures, procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs})
						}
					case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindSoftware:
						if extID == srcExt && kind == attackTypes.KindGroup {
							groupSoftwaresUsed = append(groupSoftwaresUsed, relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
						}
						if extID == tgtExt && kind == attackTypes.KindSoftware {
							softwareGroupsUsing = append(softwareGroupsUsing, relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
						}
					case srcKind == attackTypes.KindSoftware && tgtKind == attackTypes.KindTechnique:
						if extID == srcExt && kind == attackTypes.KindSoftware {
							softwareTechniquesUsed = append(softwareTechniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs})
						}
						if extID == tgtExt && kind == attackTypes.KindTechnique {
							techniqueProcedures = append(techniqueProcedures, procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs})
						}
					case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindTechnique:
						if extID == srcExt && kind == attackTypes.KindCampaign {
							campaignTechniquesUsed = append(campaignTechniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs})
						}
						if extID == tgtExt && kind == attackTypes.KindTechnique {
							techniqueProcedures = append(techniqueProcedures, procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs})
						}
					case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindSoftware:
						if extID == srcExt && kind == attackTypes.KindCampaign {
							campaignSoftwaresUsed = append(campaignSoftwaresUsed, relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
						}
						if extID == tgtExt && kind == attackTypes.KindSoftware {
							softwareCampaignsUsing = append(softwareCampaignsUsing, relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
						}
					}
				case "attributed-to":
					if srcKind != attackTypes.KindCampaign || tgtKind != attackTypes.KindGroup || srcExt == "" || tgtExt == "" {
						break
					}
					if extID == srcExt && kind == attackTypes.KindCampaign {
						campaignGroupsAttributed = append(campaignGroupsAttributed, relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
					}
					if extID == tgtExt && kind == attackTypes.KindGroup {
						groupCampaignsAttributed = append(groupCampaignsAttributed, relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
					}
				case "targets":
					if srcKind != attackTypes.KindTechnique || tgtKind != attackTypes.KindAsset || srcExt == "" || tgtExt == "" {
						break
					}
					if extID == srcExt && kind == attackTypes.KindTechnique {
						techniqueAssetsTargeted = append(techniqueAssetsTargeted, relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
					}
					if extID == tgtExt && kind == attackTypes.KindAsset {
						assetTechniquesTargeting = append(assetTechniquesTargeting, relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
					}
				case "detects":
					if srcKind != attackTypes.KindDetectStrategy || tgtKind != attackTypes.KindTechnique || srcExt == "" || tgtExt == "" {
						break
					}
					if extID == srcExt && kind == attackTypes.KindDetectStrategy {
						detStrategyTechniquesDetected = append(detStrategyTechniquesDetected, relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
					}
					if extID == tgtExt && kind == attackTypes.KindTechnique {
						techniqueDetectionStrategies = append(techniqueDetectionStrategies, relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
					}
				}
				continue
			}

			if err := attachRead(fp.Type, path, args, r); err != nil {
				return errors.Wrapf(err, "attach %s for %s", path, extID)
			}
			otherExt := externalID(fp.ExternalReferences, "mitre-attack")
			if otherExt == "" {
				continue
			}
			var otherKind attackTypes.Kind
			if oe, ok := entries[otherExt]; ok {
				otherKind = oe.kind
			}
			switch kind {
			case attackTypes.KindTactic:
				if otherKind == attackTypes.KindTechnique {
					tacticTechniques = append(tacticTechniques, otherExt)
				}
			case attackTypes.KindAnalytic:
				if otherKind == attackTypes.KindDetectStrategy {
					analyticDetectionStrategy = otherExt
				}
			case attackTypes.KindDataSource:
				if otherKind == attackTypes.KindDataComponent {
					dataSourceComponents = append(dataSourceComponents, otherExt)
				}
			}
		}

		if raw == nil {
			continue
		}

		c := commonFromRaw(raw)
		extRefs := make([]referenceTypes.Reference, 0, len(c.externalReferences))
		for _, er := range c.externalReferences {
			if er.URL == nil || *er.URL == "" {
				continue
			}
			extRefs = append(extRefs, referenceTypes.Reference{Source: er.SourceName, URL: *er.URL})
		}
		extracted := attackTypes.Attack{
			ID:          extID,
			Kind:        kind,
			Name:        c.name,
			Description: c.description,
			Domains:     slices.Clone(domains),
			Deprecated:  c.deprecated,
			Revoked:     c.revoked,
			Version:     c.version,
			Created:     c.created,
			Modified:    c.modified,
			References:  extRefs,
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MitreATTACK,
				Raws: r.Paths(),
			},
		}

		switch kind {
		case attackTypes.KindTechnique:
			ap := raw.(*attack.AttackPattern)
			isSub := derefBool(ap.XMitreIsSubtechnique)
			parent := ""
			if isSub {
				parent = techniqueParent
			}
			tactics := make([]tacticrefTypes.TacticRef, 0, len(techniqueTacticShortnames))
			for _, sn := range techniqueTacticShortnames {
				tactics = append(tactics, tacticrefTypes.TacticRef{Shortname: sn, ID: tacticShortnameToID[sn]})
			}
			extracted.Technique = techniqueTypes.Technique{
				Platforms:            slices.Clone(ap.XMitrePlatforms),
				Tactics:              tactics,
				IsSubtechnique:       isSub,
				Parent:               parent,
				Detection:            derefString(ap.XMitreDetection),
				DataSources:          slices.Clone(ap.XMitreDataSources),
				Mitigations:          techniqueMitigations,
				Procedures:           techniqueProcedures,
				PermissionsRequired:  slices.Clone(ap.XMitrePermissionsRequired),
				EffectivePermissions: slices.Clone(ap.XMitreEffectivePermissions),
				DefenseBypassed:      slices.Clone(ap.XMitreDefenseBypassed),
				ImpactType:           slices.Clone(ap.XMitreImpactType),
				NetworkRequirements:  derefBool(ap.XMitreNetworkRequirements),
				RemoteSupport:        derefBool(ap.XMitreRemoteSupport),
				Subtechniques:        techniqueSubtechniques,
				AssetsTargeted:       techniqueAssetsTargeted,
				DetectionStrategies:  techniqueDetectionStrategies,
			}
		case attackTypes.KindTactic:
			t := raw.(*attack.XMitreTactic)
			extracted.Tactic = tacticTypes.Tactic{
				Shortname:  derefString(t.XMitreShortname),
				Techniques: tacticTechniques,
			}
		case attackTypes.KindMitigation:
			extracted.Mitigation = mitigationTypes.Mitigation{
				TechniquesMitigated: mitigationTechniquesMitigated,
			}
		case attackTypes.KindGroup:
			is := raw.(*attack.IntrusionSet)
			extracted.Group = groupTypes.Group{
				Aliases:             mergeAliases(is.Aliases, is.XMitreAliases),
				TechniquesUsed:      groupTechniquesUsed,
				SoftwaresUsed:       groupSoftwaresUsed,
				CampaignsAttributed: groupCampaignsAttributed,
			}
		case attackTypes.KindSoftware:
			var aliases, xAliases, platforms []string
			var stixT string
			switch s := raw.(type) {
			case *attack.Malware:
				stixT = "malware"
				aliases = s.Aliases
				xAliases = s.XMitreAliases
				platforms = s.XMitrePlatforms
			case *attack.Tool:
				stixT = "tool"
				aliases = s.Aliases
				xAliases = s.XMitreAliases
				platforms = s.XMitrePlatforms
			}
			extracted.Software = softwareTypes.Software{
				Type:           stixT,
				Aliases:        mergeAliases(aliases, xAliases),
				Platforms:      slices.Clone(platforms),
				TechniquesUsed: softwareTechniquesUsed,
				GroupsUsing:    softwareGroupsUsing,
				CampaignsUsing: softwareCampaignsUsing,
			}
		case attackTypes.KindCampaign:
			camp := raw.(*attack.Campaign)
			extracted.Campaign = campaignTypes.Campaign{
				Aliases:          mergeAliases(camp.Aliases, nil),
				FirstSeen:        derefTime(camp.FirstSeen),
				LastSeen:         derefTime(camp.LastSeen),
				TechniquesUsed:   campaignTechniquesUsed,
				GroupsAttributed: campaignGroupsAttributed,
				SoftwaresUsed:    campaignSoftwaresUsed,
			}
		case attackTypes.KindAsset:
			as := raw.(*attack.XMitreAsset)
			related := make([]assetTypes.RelatedAsset, 0, len(as.XMitreRelatedAssets))
			for _, ra := range as.XMitreRelatedAssets {
				related = append(related, assetTypes.RelatedAsset{
					Name:        ra.Name,
					Description: ra.Description,
					Sectors:     slices.Clone(ra.RelatedAssetSectors),
				})
			}
			extracted.Asset = assetTypes.Asset{
				Platforms:           slices.Clone(as.XMitrePlatforms),
				Sectors:             slices.Clone(as.XMitreSectors),
				RelatedAssets:       related,
				TechniquesTargeting: assetTechniquesTargeting,
			}
		case attackTypes.KindDetectStrategy:
			extracted.DetectionStrategy = detectionstrategyTypes.DetectionStrategy{
				Analytics:          detStrategyAnalytics,
				TechniquesDetected: detStrategyTechniquesDetected,
			}
		case attackTypes.KindDataSource:
			ds := raw.(*attack.XMitreDataSource)
			extracted.AttackDataSource = datasourceTypes.DataSource{
				Platforms:        slices.Clone(ds.XMitrePlatforms),
				CollectionLayers: slices.Clone(ds.XMitreCollectionLayers),
				DataComponents:   dataSourceComponents,
			}
		case attackTypes.KindDataComponent:
			dc := raw.(*attack.XMitreDataComponent)
			logs := make([]datacomponentTypes.LogSource, 0, len(dc.XMitreLogSources))
			for _, ls := range dc.XMitreLogSources {
				logs = append(logs, datacomponentTypes.LogSource{Name: ls.Name, Channel: ls.Channel})
			}
			extracted.DataComponent = datacomponentTypes.DataComponent{
				DataSource: dataComponentSource,
				LogSources: logs,
			}
		case attackTypes.KindAnalytic:
			an := raw.(*attack.XMitreAnalytic)
			lrefs := make([]analyticTypes.LogSourceReference, 0, len(an.XMitreLogSourceReferences))
			for _, lr := range an.XMitreLogSourceReferences {
				lrefs = append(lrefs, analyticTypes.LogSourceReference{
					DataComponent: lr.XMitreDataComponentRef,
					Name:          lr.Name,
					Channel:       lr.Channel,
				})
			}
			mes := make([]analyticTypes.MutableElement, 0, len(an.XMitreMutableElements))
			for _, me := range an.XMitreMutableElements {
				mes = append(mes, analyticTypes.MutableElement{Field: me.Field, Description: me.Description})
			}
			extracted.Analytic = analyticTypes.Analytic{
				DetectionStrategy:   analyticDetectionStrategy,
				Platforms:           slices.Clone(an.XMitrePlatforms),
				LogSourceReferences: lrefs,
				MutableElements:     mes,
			}
		}

		outPath := filepath.Join(options.dir, "attack", fmt.Sprintf("%s.json", extID))
		if err := util.Write(outPath, extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", outPath)
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), stixdatasourceTypes.DataSource{
		ID:   sourceTypes.MitreATTACK,
		Name: new("MITRE ATT&CK"),
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

// stixPeek is the envelope Stage 1 decodes from every STIX file. The
// shared discriminator/ID/external_references trio classifies the
// record and the kind-specific cross-ref fields let Stage 1 resolve
// every UUID-based reference (Technique.TacticRefs +
// KillChainPhases, DetectionStrategy.x_mitre_analytic_refs,
// DataComponent.x_mitre_data_source_ref, Tactic.x_mitre_shortname)
// without paying for the full concrete struct. Stage 2 still reads
// each kept record concretely so the build* helpers see real fields.
type stixPeek struct {
	Type               string                     `json:"type"`
	ID                 string                     `json:"id"`
	ExternalReferences []attack.ExternalReference `json:"external_references"`
	// Every primary kind: x_mitre_domains is bundle-scoped, so the
	// same record published in multiple ATT&CK bundles contributes
	// different domains. Stage 1 unions these across occurrences so
	// cross-domain Groups / Software / Campaigns don't appear as
	// enterprise-only after first-wins dedup.
	XMitreDomains []string `json:"x_mitre_domains,omitempty"`

	// Tactic only.
	XMitreShortname *string `json:"x_mitre_shortname,omitempty"`

	// Technique only.
	TacticRefs      []string                `json:"tactic_refs,omitempty"`
	KillChainPhases []attack.KillChainPhase `json:"kill_chain_phases,omitempty"`

	// DetectionStrategy only.
	XMitreAnalyticRefs []string `json:"x_mitre_analytic_refs,omitempty"`

	// DataComponent only.
	XMitreDataSourceRef *string `json:"x_mitre_data_source_ref,omitempty"`
}

// knownStixTypes is the sorted list of STIX types the extractor knows
// how to handle (either extract or intentionally skip). Used as the
// "expected" set in unknown-type errors so CI surfaces the right hint.
var knownStixTypes = []string{
	"attack-pattern", "x-mitre-tactic", "course-of-action",
	"intrusion-set", "malware", "tool", "campaign",
	"x-mitre-asset", "x-mitre-detection-strategy", "x-mitre-analytic",
	"x-mitre-data-source", "x-mitre-data-component",
	"relationship",
	"identity", "marking-definition", "x-mitre-collection", "x-mitre-matrix",
}

// bundleDomainOf returns the ATT&CK domain string ("enterprise-attack"
// / "mobile-attack" / "ics-attack") implied by path's bundle
// subdirectory under root. The raw repo uses bare bundle names
// ("enterprise/", "mobile/", "ics/"), so we append "-attack" when the
// directory name doesn't already end with that suffix. An empty
// return string makes the artifact filter at Stage 1a reject the file
// (which is what we want when path doesn't live under a recognised
// bundle dir).
func bundleDomainOf(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	dir, _, ok := strings.Cut(rel, string(filepath.Separator))
	if !ok || dir == "" {
		return ""
	}
	if strings.HasSuffix(dir, "-attack") {
		return dir
	}
	return dir + "-attack"
}

func peekPrimary(path string) (stixPeek, error) {
	f, err := os.Open(path)
	if err != nil {
		return stixPeek{}, errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()
	var p stixPeek
	if err := json.UnmarshalRead(f, &p); err != nil {
		return stixPeek{}, errors.Wrapf(err, "decode %s", path)
	}
	return p, nil
}

// attachRead registers the path into r by reading the file as the
// given STIX type. JSONReader's path tracking dedupes within a reader,
// so the same file referenced by multiple relationships only appears
// once in the final raws list. Unknown stixType is a silent no-op
// because the input may include STIX kinds the extractor doesn't keep
// (matching attachCrossRef's old behaviour).
func attachRead(stixType, path, args string, r *utiljson.JSONReader) error {
	if path == "" {
		return nil
	}
	switch stixType {
	case "relationship":
		return r.Read(path, args, new(attack.Relationship))
	case "attack-pattern":
		return r.Read(path, args, new(attack.AttackPattern))
	case "x-mitre-tactic":
		return r.Read(path, args, new(attack.XMitreTactic))
	case "course-of-action":
		return r.Read(path, args, new(attack.CourseOfAction))
	case "intrusion-set":
		return r.Read(path, args, new(attack.IntrusionSet))
	case "malware":
		return r.Read(path, args, new(attack.Malware))
	case "tool":
		return r.Read(path, args, new(attack.Tool))
	case "campaign":
		return r.Read(path, args, new(attack.Campaign))
	case "x-mitre-asset":
		return r.Read(path, args, new(attack.XMitreAsset))
	case "x-mitre-detection-strategy":
		return r.Read(path, args, new(attack.XMitreDetectionStrategy))
	case "x-mitre-analytic":
		return r.Read(path, args, new(attack.XMitreAnalytic))
	case "x-mitre-data-source":
		return r.Read(path, args, new(attack.XMitreDataSource))
	case "x-mitre-data-component":
		return r.Read(path, args, new(attack.XMitreDataComponent))
	}
	return nil
}

// readConcrete is the Stage 2 dispatcher: given the STIX type already
// discovered in Stage 1, decode the file into the matching struct
// using the supplied JSONReader so the file path is recorded for
// provenance. Returns the raw struct (stored in primaryEntry.raw via
// type assertion downstream).
func readConcrete(stixType, path, args string, r *utiljson.JSONReader) (any, error) {
	switch stixType {
	case "attack-pattern":
		var o attack.AttackPattern
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "x-mitre-tactic":
		var o attack.XMitreTactic
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "course-of-action":
		var o attack.CourseOfAction
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "intrusion-set":
		var o attack.IntrusionSet
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "malware":
		var o attack.Malware
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "tool":
		var o attack.Tool
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "campaign":
		var o attack.Campaign
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "x-mitre-asset":
		var o attack.XMitreAsset
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "x-mitre-detection-strategy":
		var o attack.XMitreDetectionStrategy
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "x-mitre-analytic":
		var o attack.XMitreAnalytic
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "x-mitre-data-source":
		var o attack.XMitreDataSource
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	case "x-mitre-data-component":
		var o attack.XMitreDataComponent
		if err := r.Read(path, args, &o); err != nil {
			return nil, errors.Wrapf(err, "read json %s", path)
		}
		return &o, nil
	}
	// Unreachable when callers honour Stage 1's stixTypeToKind filter,
	// but defensive in case the dispatcher and the table drift.
	return nil, errors.Errorf("unexpected STIX type for readConcrete: %q", stixType)
}

// decodeRelationship reads a STIX relationship file. Stage 1c uses
// this without a JSONReader because relationship files don't carry
// content for the canonical record — their paths are tracked per-entry
// by the per-extID file lists that Stage 2 walks.
func decodeRelationship(path string) (attack.Relationship, error) {
	f, err := os.Open(path)
	if err != nil {
		return attack.Relationship{}, errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()
	var r attack.Relationship
	if err := json.UnmarshalRead(f, &r); err != nil {
		return attack.Relationship{}, errors.Wrapf(err, "decode %s", path)
	}
	return r, nil
}


func derefTime(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}

// toReferences converts a STIX external_references slice to the
// canonical reference list, skipping entries without a URL (those tend
// to be ATT&CK ID stubs already represented by the ID field).
func toReferences(ers []attack.ExternalReference) []referenceTypes.Reference {
	if len(ers) == 0 {
		return nil
	}
	out := make([]referenceTypes.Reference, 0, len(ers))
	for _, er := range ers {
		if er.URL == nil {
			continue
		}
		out = append(out, referenceTypes.Reference{
			Source: er.SourceName,
			URL:    *er.URL,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// commonFields are the STIX object fields every ATT&CK primary kind
// shares — Stage 2 reads them via commonFromRaw and copies into the
// canonical Attack header.
type commonFields struct {
	name               string
	description        string
	domains            []string
	deprecated         bool
	revoked            bool
	version            string
	created            time.Time
	modified           time.Time
	externalReferences []attack.ExternalReference
}

func commonFromRaw(raw any) commonFields {
	switch o := raw.(type) {
	case *attack.AttackPattern:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.XMitreTactic:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.CourseOfAction:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.IntrusionSet:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.Malware:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.Tool:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.Campaign:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.XMitreAsset:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.XMitreDetectionStrategy:
		return commonFields{derefString(o.Name), "", o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.XMitreAnalytic:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.XMitreDataSource:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	case *attack.XMitreDataComponent:
		return commonFields{derefString(o.Name), derefString(o.Description), o.XMitreDomains, derefBool(o.XMitreDeprecated), derefBool(o.Revoked), derefString(o.XMitreVersion), o.Created, o.Modified, o.ExternalReferences}
	}
	return commonFields{}
}

func mergeAliases(stixAliases, mitreAliases []string) []string {
	seen := make(map[string]struct{}, len(stixAliases)+len(mitreAliases))
	out := make([]string, 0, len(stixAliases)+len(mitreAliases))
	for _, group := range [][]string{stixAliases, mitreAliases} {
		for _, a := range group {
			if a == "" {
				continue
			}
			if _, ok := seen[a]; ok {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	return out
}

func externalID(refs []attack.ExternalReference, sourceName string) string {
	for _, r := range refs {
		if r.SourceName == sourceName && r.ExternalID != nil {
			return *r.ExternalID
		}
	}
	return ""
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}
