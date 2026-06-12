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
	tacticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/tactic"
	tacticrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/tacticref"
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

// entryInfo carries every per-ext-ID detail Stage 2 needs to build one
// canonical record. Stage 1 populates a single map[extID]entryInfo
// instead of five parallel maps. Missing ext-IDs are expressed by a
// failed map lookup; the map never stores a zero value on purpose.
//
// The three path collections are kept separate so Stage 2 doesn't have
// to re-classify a single flat list:
//   - paths: this ext-ID's own primary files (1..N bundle copies)
//   - rels:  relationship files this ext-ID participates in, keyed by
//     STIX UUID so cross-bundle copies of the same logical
//     relationship dedupe naturally
//   - refs:  cross-referenced primary files (other side of relationships
//     or forward refs); raws-only, processed once each
type entryInfo struct {
	kind     attackTypes.Kind
	stixType string
	peek     stixPeek
	paths    []string
	rels     map[string]string // STIX UUID → one path (any bundle copy)
	refs     []string
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
	// to resolve relationships (uuids). Nothing else crosses the
	// Stage 1 ↔ Stage 2 boundary.
	entries := make(map[string]entryInfo)
	uuids := make(map[string]uuidInfo)

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
		// Relationships are handled in Stage 1c; identity /
		// marking-definition / x-mitre-collection / x-mitre-matrix
		// carry no per-record content surfaced by ATT&CK web pages
		// and simply leave no trace. Everything else dispatches to
		// the Kind we project this STIX type onto; an unknown type
		// is a CI failure so the extractor catches MITRE schema
		// drift.
		var kind attackTypes.Kind
		switch peek.Type {
		case "relationship", "identity", "marking-definition", "x-mitre-collection", "x-mitre-matrix":
			return nil
		case "attack-pattern":
			kind = attackTypes.KindTechnique
		case "x-mitre-tactic":
			kind = attackTypes.KindTactic
		case "course-of-action":
			kind = attackTypes.KindMitigation
		case "intrusion-set":
			kind = attackTypes.KindGroup
		case "malware", "tool":
			kind = attackTypes.KindSoftware
		case "campaign":
			kind = attackTypes.KindCampaign
		case "x-mitre-asset":
			kind = attackTypes.KindAsset
		case "x-mitre-detection-strategy":
			kind = attackTypes.KindDetectStrategy
		case "x-mitre-analytic":
			kind = attackTypes.KindAnalytic
		case "x-mitre-data-source":
			kind = attackTypes.KindDataSource
		case "x-mitre-data-component":
			kind = attackTypes.KindDataComponent
		default:
			return errors.Errorf("unexpected STIX type. expected: %q, actual: %q", []string{
				"attack-pattern", "x-mitre-tactic", "course-of-action",
				"intrusion-set", "malware", "tool", "campaign",
				"x-mitre-asset", "x-mitre-detection-strategy", "x-mitre-analytic",
				"x-mitre-data-source", "x-mitre-data-component",
				"relationship",
				"identity", "marking-definition", "x-mitre-collection", "x-mitre-matrix",
			}, peek.Type)
		}
		// MITRE distributes referenced objects with every bundle that
		// needs them: T1047 (Enterprise-only) is mirrored into the
		// mobile/ and ics/ bundle dirs because those bundles reference
		// it from their relationships. Each copy declares its true
		// domain in x_mitre_domains, so we keep only files whose
		// bundle dir matches one of their declared domains; the rest
		// are distribution artifacts we drop here before any indexing.
		b := bundleOf(args, path)
		if !slices.Contains(peek.XMitreDomains, b.domain) {
			return nil
		}
		extID := externalID(peek.ExternalReferences, "mitre-attack")
		if extID == "" && (peek.Revoked || peek.XMitreDeprecated) {
			// Deprecated / revoked records from before the
			// source_name unification still ship with the bundle's
			// legacy source_name (mitre-ics-attack /
			// mitre-mobile-attack) and never got migrated. Fall
			// back so we surface their canonical ATT&CK IDs
			// (T0xxx, etc.). Enterprise's b.sourceName is already
			// mitre-attack, so the second call is a harmless
			// no-op there.
			extID = externalID(peek.ExternalReferences, b.sourceName)
		}
		if extID == "" {
			// Live records must carry the canonical mitre-attack
			// external_id; anything else is schema drift CI should
			// surface.
			return errors.Errorf("missing mitre-attack external_id in %s (type %q)", path, peek.Type)
		}

		uuids[peek.ID] = uuidInfo{ext: extID, kind: kind, path: path}

		e, ok := entries[extID]
		if !ok {
			e = entryInfo{
				kind:     kind,
				stixType: peek.Type,
				peek:     peek,
				rels:     make(map[string]string),
			}
		}
		e.paths = append(e.paths, path)
		entries[extID] = e

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	// Stage 1b: per-extID, link the files Stage 2 will need to build
	// the cross-ref fields. Forward refs (e.g. Technique → Tactic via
	// KillChainPhases) and reverse refs (Tactic → Techniques) both
	// surface as file membership in entries[id].files, so Stage 2
	// doesn't need a global edge index to know which files to open.
	for extID, e := range entries {
		switch e.kind {
		case attackTypes.KindTechnique:
			// KillChainPhases name the Tactic by its shortname; resolve
			// to the Tactic's ext-ID so we can add the Technique to that
			// Tactic's file list (for Tactic.Techniques reverse).
			for _, kc := range e.peek.Technique.KillChainPhases {
				switch kc.KillChainName {
				case "mitre-attack", "mitre-ics-attack", "mitre-mobile-attack":
					for tExt, tac := range entries {
						if tac.kind != attackTypes.KindTactic || tac.peek.Tactic.XMitreShortname != kc.PhaseName {
							continue
						}
						tac.refs = append(tac.refs, e.paths...)
						entries[tExt] = tac
						break
					}
				}
			}
			entries[extID] = e
		case attackTypes.KindDetectStrategy:
			for _, ar := range e.peek.DetectStrategy.XMitreAnalyticRefs {
				u, ok := uuids[ar]
				if !ok {
					continue
				}
				an, ok := entries[u.ext]
				if !ok {
					continue
				}
				e.refs = append(e.refs, an.paths...)
				an.refs = append(an.refs, e.paths...)
				entries[u.ext] = an
			}
			entries[extID] = e
		case attackTypes.KindDataComponent:
			if e.peek.DataComponent.XMitreDataSourceRef == nil {
				continue
			}
			u, ok := uuids[*e.peek.DataComponent.XMitreDataSourceRef]
			if !ok {
				continue
			}
			ds, ok := entries[u.ext]
			if !ok {
				continue
			}
			e.refs = append(e.refs, ds.paths...)
			ds.refs = append(ds.refs, e.paths...)
			entries[u.ext] = ds
			entries[extID] = e
		}
	}

	// Stage 1c: link relationship files into both sides' file lists,
	// plus every cross-domain copy of the other-side primary so Stage 2
	// can replay them for provenance without a global edge index.
	// ATT&CK only ships three bundles (enterprise / ics / mobile) and
	// bundleOf already hard-codes that set, so iterating an explicit
	// list keeps Stage 1a and Stage 1c in sync.
	for _, dom := range []string{"enterprise", "ics", "mobile"} {
		if err := filepath.WalkDir(filepath.Join(args, dom, "relationship"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return errors.Wrapf(err, "open %s", path)
			}
			defer f.Close()

			var r attack.Relationship
			if err := json.UnmarshalRead(f, &r); err != nil {
				return errors.Wrapf(err, "decode %s", path)
			}

			src, srcOK := entries[uuids[r.SourceRef].ext]
			tgt, tgtOK := entries[uuids[r.TargetRef].ext]
			if !srcOK || !tgtOK {
				return errors.Errorf("relationship %s references unindexed UUID (src=%s, tgt=%s)", path, r.SourceRef, r.TargetRef)
			}
			src.rels[r.ID] = path
			src.refs = append(src.refs, tgt.paths...)
			tgt.rels[r.ID] = path
			tgt.refs = append(tgt.refs, src.paths...)
			entries[uuids[r.SourceRef].ext] = src
			entries[uuids[r.TargetRef].ext] = tgt

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(args, dom, "relationship"))
		}
	}

	// Stage 2: for each unique ext-ID, walk its file list. Each file is
	// either this entry's primary (or a cross-domain copy of it), a
	// relationship file we parse for src/tgt direction + per-edge
	// content, or another primary's file pulled in by cross-ref. The
	// per-entry rels struct accumulates the kind-specific fields and
	// is then handed to convert() unchanged.
	for extID, e := range entries {
		r := utiljson.NewJSONReader()
		domains := slices.Clone(e.peek.XMitreDomains)

		// Per-kind accumulators. Only the slots for the entry's own
		// kind get populated below; every other group stays zero so
		// the final Attack struct literal sees just the natural
		// defaults. Grouping by kind makes it obvious at a glance
		// which fields belong to which sub-struct.
		var (
			technique struct {
				parent              string
				subtechniques       []string
				tactics             []tacticrefTypes.TacticRef
				procedures          []procedureTypes.Procedure
				mitigations         []relatedrefTypes.RelatedRef
				assetsTargeted      []relatedrefTypes.RelatedRef
				detectionStrategies []relatedrefTypes.RelatedRef
			}
			mitigation struct {
				techniquesMitigated []relatedrefTypes.RelatedRef
			}
			group struct {
				techniquesUsed      []techniqueusedTypes.TechniqueUsed
				softwaresUsed       []relatedrefTypes.RelatedRef
				campaignsAttributed []relatedrefTypes.RelatedRef
			}
			software struct {
				techniquesUsed []techniqueusedTypes.TechniqueUsed
				groupsUsing    []relatedrefTypes.RelatedRef
				campaignsUsing []relatedrefTypes.RelatedRef
			}
			campaign struct {
				techniquesUsed   []techniqueusedTypes.TechniqueUsed
				groupsAttributed []relatedrefTypes.RelatedRef
				softwaresUsed    []relatedrefTypes.RelatedRef
			}
			tactic struct {
				techniques []string
			}
			asset struct {
				techniquesTargeting []relatedrefTypes.RelatedRef
			}
			detectStrategy struct {
				analytics          []string
				techniquesDetected []relatedrefTypes.RelatedRef
			}
			analytic struct {
				detectionStrategy string
			}
			dataSource struct {
				components []string
			}
			dataComponent struct {
				source string
			}
		)

		// Forward cross-refs come from the entry's own peek. Tactic
		// references resolve to shortname+ID by reading sibling entries
		// directly, so no precomputed shortname/UUID lookup tables are
		// needed.
		switch e.kind {
		case attackTypes.KindTechnique:
			for _, kc := range e.peek.Technique.KillChainPhases {
				switch kc.KillChainName {
				case "mitre-attack", "mitre-ics-attack", "mitre-mobile-attack":
					var tacticExt string
					for tExt, tac := range entries {
						if tac.kind != attackTypes.KindTactic || tac.peek.Tactic.XMitreShortname != kc.PhaseName {
							continue
						}
						tacticExt = tExt
						break
					}
					if tacticExt == "" {
						return errors.Errorf("technique %s references kill_chain_phase shortname %q with no matching x-mitre-tactic", extID, kc.PhaseName)
					}
					technique.tactics = append(technique.tactics, tacticrefTypes.TacticRef{Shortname: kc.PhaseName, ID: tacticExt})
				}
			}
		case attackTypes.KindDetectStrategy:
			for _, ar := range e.peek.DetectStrategy.XMitreAnalyticRefs {
				if u, ok := uuids[ar]; ok {
					detectStrategy.analytics = append(detectStrategy.analytics, u.ext)
				}
			}
		case attackTypes.KindDataComponent:
			if e.peek.DataComponent.XMitreDataSourceRef != nil {
				if u, ok := uuids[*e.peek.DataComponent.XMitreDataSourceRef]; ok {
					dataComponent.source = u.ext
				}
			}
		}

		// Stage 2a: cross-domain copies of the same record (multi-domain
		// Groups / Software / Campaigns) contribute provenance and their
		// declared XMitreDomains subset, but nothing else. r.Read folds
		// the path registration and the partial decode into one pass.
		// The canonical e.paths[0] copy is decoded inside the kind
		// switch below so the concrete type is in scope when its
		// kind-specific sub-struct is built.
		for _, path := range e.paths[1:] {
			var p stixPeek
			if err := r.Read(path, args, &p); err != nil {
				return errors.Wrapf(err, "read self %s for %s", path, extID)
			}
			for _, d := range p.XMitreDomains {
				if !slices.Contains(domains, d) {
					domains = append(domains, d)
				}
			}
		}

		// Stage 2b: relationships keyed by STIX UUID. Cross-bundle
		// copies of the same logical relationship were collapsed at
		// Stage 1c, so each edge is dispatched exactly once. r.Read
		// both decodes the edge and registers its path for raws in
		// a single pass.
		for _, path := range e.rels {
			var rel attack.Relationship
			if err := r.Read(path, args, &rel); err != nil {
				return errors.Wrapf(err, "read relationship %s for %s", path, extID)
			}
			src := uuids[rel.SourceRef]
			tgt := uuids[rel.TargetRef]
			desc := ""
			if rel.Description != nil {
				desc = *rel.Description
			}
			refs := toReferences(rel.ExternalReferences)

			switch rel.RelationshipType {
			case "subtechnique-of":
				if e.kind != attackTypes.KindTechnique {
					return errors.Errorf("subtechnique-of relationship %s reached non-Technique endpoint %s (kind %v)", rel.ID, extID, e.kind)
				}
				if extID == src.ext {
					technique.parent = tgt.ext
				}
				if extID == tgt.ext {
					technique.subtechniques = append(technique.subtechniques, src.ext)
				}
			case "mitigates":
				if src.kind != attackTypes.KindMitigation || tgt.kind != attackTypes.KindTechnique {
					return errors.Errorf("mitigates relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if extID == src.ext {
					mitigation.techniquesMitigated = append(mitigation.techniquesMitigated, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if extID == tgt.ext {
					technique.mitigations = append(technique.mitigations, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "uses":
				switch {
				case src.kind == attackTypes.KindGroup && tgt.kind == attackTypes.KindTechnique:
					if extID == src.ext {
						group.techniquesUsed = append(group.techniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgt.ext, Description: desc, References: refs})
					}
					if extID == tgt.ext {
						technique.procedures = append(technique.procedures, procedureTypes.Procedure{AttackerID: src.ext, Description: desc, References: refs})
					}
				case src.kind == attackTypes.KindGroup && tgt.kind == attackTypes.KindSoftware:
					if extID == src.ext {
						group.softwaresUsed = append(group.softwaresUsed, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
					}
					if extID == tgt.ext {
						software.groupsUsing = append(software.groupsUsing, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
					}
				case src.kind == attackTypes.KindSoftware && tgt.kind == attackTypes.KindTechnique:
					if extID == src.ext {
						software.techniquesUsed = append(software.techniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgt.ext, Description: desc, References: refs})
					}
					if extID == tgt.ext {
						technique.procedures = append(technique.procedures, procedureTypes.Procedure{AttackerID: src.ext, Description: desc, References: refs})
					}
				case src.kind == attackTypes.KindCampaign && tgt.kind == attackTypes.KindTechnique:
					if extID == src.ext {
						campaign.techniquesUsed = append(campaign.techniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgt.ext, Description: desc, References: refs})
					}
					if extID == tgt.ext {
						technique.procedures = append(technique.procedures, procedureTypes.Procedure{AttackerID: src.ext, Description: desc, References: refs})
					}
				case src.kind == attackTypes.KindCampaign && tgt.kind == attackTypes.KindSoftware:
					if extID == src.ext {
						campaign.softwaresUsed = append(campaign.softwaresUsed, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
					}
					if extID == tgt.ext {
						software.campaignsUsing = append(software.campaignsUsing, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
					}
				default:
					return errors.Errorf("uses relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
			case "attributed-to":
				if src.kind != attackTypes.KindCampaign || tgt.kind != attackTypes.KindGroup {
					return errors.Errorf("attributed-to relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if extID == src.ext {
					campaign.groupsAttributed = append(campaign.groupsAttributed, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if extID == tgt.ext {
					group.campaignsAttributed = append(group.campaignsAttributed, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "targets":
				if src.kind != attackTypes.KindTechnique || tgt.kind != attackTypes.KindAsset {
					return errors.Errorf("targets relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if extID == src.ext {
					technique.assetsTargeted = append(technique.assetsTargeted, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if extID == tgt.ext {
					asset.techniquesTargeting = append(asset.techniquesTargeting, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "detects":
				if src.kind != attackTypes.KindDetectStrategy || tgt.kind != attackTypes.KindTechnique {
					return errors.Errorf("detects relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if extID == src.ext {
					detectStrategy.techniquesDetected = append(detectStrategy.techniquesDetected, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if extID == tgt.ext {
					technique.detectionStrategies = append(technique.detectionStrategies, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "revoked-by":
				// MITRE uses revoked-by to point a withdrawn object at
				// its replacement. The Revoked flag on the source
				// already conveys that to consumers, so we keep the
				// relationship file in raws (via the r.Read above) but
				// do not surface an edge.
			default:
				return errors.Errorf("unexpected relationship_type %q in %s", rel.RelationshipType, rel.ID)
			}
		}

		// Stage 2c: cross-referenced primary files (other side of
		// relationships or forward refs). r.Read folds the path
		// registration for raws and the partial decode (just enough
		// to resolve the UUID via Stage 1's uuid index — legacy
		// source_names included) into a single pass.
		for _, path := range e.refs {
			var fp stixPeek
			if err := r.Read(path, args, &fp); err != nil {
				return errors.Wrapf(err, "read ref %s for %s", path, extID)
			}
			otherExt := uuids[fp.ID].ext
			if otherExt == "" {
				return errors.Errorf("file %s (id %s) was not indexed in Stage 1 but is referenced from %s", path, fp.ID, extID)
			}
			otherKind := entries[otherExt].kind
			switch e.kind {
			case attackTypes.KindTactic:
				if otherKind == attackTypes.KindTechnique {
					tactic.techniques = append(tactic.techniques, otherExt)
				}
			case attackTypes.KindAnalytic:
				if otherKind == attackTypes.KindDetectStrategy {
					analytic.detectionStrategy = otherExt
				}
			case attackTypes.KindDataSource:
				if otherKind == attackTypes.KindDataComponent {
					dataSource.components = append(dataSource.components, otherExt)
				}
			}
		}

		// Final assembly: each case decodes e.paths[0] into the kind's
		// concrete type and builds the canonical Attack record inline.
		// The common-header fields repeat across cases; keeping them in
		// every literal makes each case self-contained and lets the
		// concrete type stay in scope without an any-typed intermediate
		// or a separate helper indirection.
		var extracted attackTypes.Attack
		switch e.kind {
		case attackTypes.KindTechnique:
			var ap attack.AttackPattern
			if err := r.Read(e.paths[0], args, &ap); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			isSub := deref(ap.XMitreIsSubtechnique)
			parent := ""
			if isSub {
				parent = technique.parent
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(ap.Name),
				Description: deref(ap.Description),
				Domains:     domains,
				Deprecated:  deref(ap.XMitreDeprecated),
				Revoked:     deref(ap.Revoked),
				Version:     deref(ap.XMitreVersion),
				Created:     ap.Created,
				Modified:    ap.Modified,
				References:  toReferences(ap.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Technique: techniqueTypes.Technique{
					Platforms:            ap.XMitrePlatforms,
					Tactics:              technique.tactics,
					IsSubtechnique:       isSub,
					Parent:               parent,
					Detection:            deref(ap.XMitreDetection),
					DataSources:          ap.XMitreDataSources,
					Mitigations:          technique.mitigations,
					Procedures:           technique.procedures,
					PermissionsRequired:  ap.XMitrePermissionsRequired,
					EffectivePermissions: ap.XMitreEffectivePermissions,
					DefenseBypassed:      ap.XMitreDefenseBypassed,
					ImpactType:           ap.XMitreImpactType,
					NetworkRequirements:  deref(ap.XMitreNetworkRequirements),
					RemoteSupport:        deref(ap.XMitreRemoteSupport),
					Subtechniques:        technique.subtechniques,
					AssetsTargeted:       technique.assetsTargeted,
					DetectionStrategies:  technique.detectionStrategies,
				},
			}
		case attackTypes.KindTactic:
			var t attack.XMitreTactic
			if err := r.Read(e.paths[0], args, &t); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(t.Name),
				Description: deref(t.Description),
				Domains:     domains,
				Deprecated:  deref(t.XMitreDeprecated),
				Revoked:     deref(t.Revoked),
				Version:     deref(t.XMitreVersion),
				Created:     t.Created,
				Modified:    t.Modified,
				References:  toReferences(t.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Tactic: tacticTypes.Tactic{
					Shortname:  deref(t.XMitreShortname),
					Techniques: tactic.techniques,
				},
			}
		case attackTypes.KindMitigation:
			var m attack.CourseOfAction
			if err := r.Read(e.paths[0], args, &m); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(m.Name),
				Description: deref(m.Description),
				Domains:     domains,
				Deprecated:  deref(m.XMitreDeprecated),
				Revoked:     deref(m.Revoked),
				Version:     deref(m.XMitreVersion),
				Created:     m.Created,
				Modified:    m.Modified,
				References:  toReferences(m.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Mitigation: mitigationTypes.Mitigation{
					TechniquesMitigated: mitigation.techniquesMitigated,
				},
			}
		case attackTypes.KindGroup:
			var is attack.IntrusionSet
			if err := r.Read(e.paths[0], args, &is); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(is.Name),
				Description: deref(is.Description),
				Domains:     domains,
				Deprecated:  deref(is.XMitreDeprecated),
				Revoked:     deref(is.Revoked),
				Version:     deref(is.XMitreVersion),
				Created:     is.Created,
				Modified:    is.Modified,
				References:  toReferences(is.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Group: groupTypes.Group{
					Aliases:             is.Aliases,
					TechniquesUsed:      group.techniquesUsed,
					SoftwaresUsed:       group.softwaresUsed,
					CampaignsAttributed: group.campaignsAttributed,
				},
			}
		case attackTypes.KindSoftware:
			// Software is either malware or tool; the literal differs
			// only in the concrete type backing its common fields, so
			// build it inside each inner arm.
			switch e.stixType {
			case "malware":
				var m attack.Malware
				if err := r.Read(e.paths[0], args, &m); err != nil {
					return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
				}
				extracted = attackTypes.Attack{
					ID:          extID,
					Kind:        e.kind,
					Name:        deref(m.Name),
					Description: deref(m.Description),
					Domains:     domains,
					Deprecated:  deref(m.XMitreDeprecated),
					Revoked:     deref(m.Revoked),
					Version:     deref(m.XMitreVersion),
					Created:     m.Created,
					Modified:    m.Modified,
					References:  toReferences(m.ExternalReferences),
					DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
					Software: softwareTypes.Software{
						Type:           e.stixType,
						Aliases:        m.XMitreAliases,
						Platforms:      m.XMitrePlatforms,
						TechniquesUsed: software.techniquesUsed,
						GroupsUsing:    software.groupsUsing,
						CampaignsUsing: software.campaignsUsing,
					},
				}
			case "tool":
				var t attack.Tool
				if err := r.Read(e.paths[0], args, &t); err != nil {
					return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
				}
				extracted = attackTypes.Attack{
					ID:          extID,
					Kind:        e.kind,
					Name:        deref(t.Name),
					Description: deref(t.Description),
					Domains:     domains,
					Deprecated:  deref(t.XMitreDeprecated),
					Revoked:     deref(t.Revoked),
					Version:     deref(t.XMitreVersion),
					Created:     t.Created,
					Modified:    t.Modified,
					References:  toReferences(t.ExternalReferences),
					DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
					Software: softwareTypes.Software{
						Type:           e.stixType,
						Aliases:        t.XMitreAliases,
						Platforms:      t.XMitrePlatforms,
						TechniquesUsed: software.techniquesUsed,
						GroupsUsing:    software.groupsUsing,
						CampaignsUsing: software.campaignsUsing,
					},
				}
			}
		case attackTypes.KindCampaign:
			var camp attack.Campaign
			if err := r.Read(e.paths[0], args, &camp); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(camp.Name),
				Description: deref(camp.Description),
				Domains:     domains,
				Deprecated:  deref(camp.XMitreDeprecated),
				Revoked:     deref(camp.Revoked),
				Version:     deref(camp.XMitreVersion),
				Created:     camp.Created,
				Modified:    camp.Modified,
				References:  toReferences(camp.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Campaign: campaignTypes.Campaign{
					Aliases:          camp.Aliases,
					FirstSeen:        deref(camp.FirstSeen),
					LastSeen:         deref(camp.LastSeen),
					TechniquesUsed:   campaign.techniquesUsed,
					GroupsAttributed: campaign.groupsAttributed,
					SoftwaresUsed:    campaign.softwaresUsed,
				},
			}
		case attackTypes.KindAsset:
			var as attack.XMitreAsset
			if err := r.Read(e.paths[0], args, &as); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			related := make([]assetTypes.RelatedAsset, 0, len(as.XMitreRelatedAssets))
			for _, ra := range as.XMitreRelatedAssets {
				related = append(related, assetTypes.RelatedAsset{
					Name:        ra.Name,
					Description: ra.Description,
					Sectors:     ra.RelatedAssetSectors,
				})
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(as.Name),
				Description: deref(as.Description),
				Domains:     domains,
				Deprecated:  deref(as.XMitreDeprecated),
				Revoked:     deref(as.Revoked),
				Version:     deref(as.XMitreVersion),
				Created:     as.Created,
				Modified:    as.Modified,
				References:  toReferences(as.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Asset: assetTypes.Asset{
					Platforms:           as.XMitrePlatforms,
					Sectors:             as.XMitreSectors,
					RelatedAssets:       related,
					TechniquesTargeting: asset.techniquesTargeting,
				},
			}
		case attackTypes.KindDetectStrategy:
			var ds attack.XMitreDetectionStrategy
			if err := r.Read(e.paths[0], args, &ds); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:   extID,
				Kind: e.kind,
				Name: deref(ds.Name),
				// XMitreDetectionStrategy has no description field.
				Domains:    domains,
				Deprecated: deref(ds.XMitreDeprecated),
				Revoked:    deref(ds.Revoked),
				Version:    deref(ds.XMitreVersion),
				Created:    ds.Created,
				Modified:   ds.Modified,
				References: toReferences(ds.ExternalReferences),
				DataSource: sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				DetectionStrategy: detectionstrategyTypes.DetectionStrategy{
					Analytics:          detectStrategy.analytics,
					TechniquesDetected: detectStrategy.techniquesDetected,
				},
			}
		case attackTypes.KindDataSource:
			var ds attack.XMitreDataSource
			if err := r.Read(e.paths[0], args, &ds); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(ds.Name),
				Description: deref(ds.Description),
				Domains:     domains,
				Deprecated:  deref(ds.XMitreDeprecated),
				Revoked:     deref(ds.Revoked),
				Version:     deref(ds.XMitreVersion),
				Created:     ds.Created,
				Modified:    ds.Modified,
				References:  toReferences(ds.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				AttackDataSource: datasourceTypes.DataSource{
					Platforms:        ds.XMitrePlatforms,
					CollectionLayers: ds.XMitreCollectionLayers,
					DataComponents:   dataSource.components,
				},
			}
		case attackTypes.KindDataComponent:
			var dc attack.XMitreDataComponent
			if err := r.Read(e.paths[0], args, &dc); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			logs := make([]datacomponentTypes.LogSource, 0, len(dc.XMitreLogSources))
			for _, ls := range dc.XMitreLogSources {
				logs = append(logs, datacomponentTypes.LogSource{Name: ls.Name, Channel: ls.Channel})
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(dc.Name),
				Description: deref(dc.Description),
				Domains:     domains,
				Deprecated:  deref(dc.XMitreDeprecated),
				Revoked:     deref(dc.Revoked),
				Version:     deref(dc.XMitreVersion),
				Created:     dc.Created,
				Modified:    dc.Modified,
				References:  toReferences(dc.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				DataComponent: datacomponentTypes.DataComponent{
					DataSource: dataComponent.source,
					LogSources: logs,
				},
			}
		case attackTypes.KindAnalytic:
			var an attack.XMitreAnalytic
			if err := r.Read(e.paths[0], args, &an); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
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
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        e.kind,
				Name:        deref(an.Name),
				Description: deref(an.Description),
				Domains:     domains,
				Deprecated:  deref(an.XMitreDeprecated),
				Revoked:     deref(an.Revoked),
				Version:     deref(an.XMitreVersion),
				Created:     an.Created,
				Modified:    an.Modified,
				References:  toReferences(an.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Analytic: analyticTypes.Analytic{
					DetectionStrategy:   analytic.detectionStrategy,
					Platforms:           an.XMitrePlatforms,
					LogSourceReferences: lrefs,
					MutableElements:     mes,
				},
			}
		default:
			// Stage 1a's stixType switch should make this unreachable;
			// surface the drift if a new Kind ever gets added without a
			// matching case here.
			return errors.Errorf("unexpected kind for %s: %s", extID, e.kind)
		}

		if err := util.Write(filepath.Join(options.dir, "attack", fmt.Sprintf("%s.json", extID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "attack", fmt.Sprintf("%s.json", extID)))
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
// every UUID-based reference (Technique.KillChainPhases,
// DetectionStrategy.x_mitre_analytic_refs,
// DataComponent.x_mitre_data_source_ref, Tactic.x_mitre_shortname)
// without paying for the full concrete struct. Stage 2 still reads
// each kept record concretely so the build* helpers see real fields.
type stixPeek struct {
	Type               string                     `json:"type"`
	ID                 string                     `json:"id"`
	ExternalReferences []attack.ExternalReference `json:"external_references"`
	// Revoked / XMitreDeprecated let Stage 1a recognise the legacy
	// ICS / Mobile records that pre-date source_name unification:
	// they have no mitre-attack external_id, so we drop them without
	// erroring on the missing canonical ID.
	Revoked          bool `json:"revoked,omitempty"`
	XMitreDeprecated bool `json:"x_mitre_deprecated,omitempty"`
	// Every primary kind: x_mitre_domains is bundle-scoped, so the
	// same record published in multiple ATT&CK bundles contributes
	// different domains. Stage 1 unions these across occurrences so
	// cross-domain Groups / Software / Campaigns don't appear as
	// enterprise-only after first-wins dedup.
	XMitreDomains []string `json:"x_mitre_domains,omitempty"`

	// Kind-specific cross-ref fields. Each sub-struct's JSON fields
	// are inlined at the parent level (json:",inline"), matching STIX's
	// flat schema while keeping Stage 1/2 access sites obvious about
	// which Kind they're touching.
	Tactic struct {
		XMitreShortname string `json:"x_mitre_shortname,omitempty"`
	} `json:",inline"`
	Technique struct {
		KillChainPhases []attack.KillChainPhase `json:"kill_chain_phases,omitempty"`
	} `json:",inline"`
	DetectStrategy struct {
		XMitreAnalyticRefs []string `json:"x_mitre_analytic_refs,omitempty"`
	} `json:",inline"`
	DataComponent struct {
		XMitreDataSourceRef *string `json:"x_mitre_data_source_ref,omitempty"`
	} `json:",inline"`
}

// bundleInfo carries the ATT&CK bundle identity for a file: its
// x_mitre_domains value (used by the Stage 1a distribution-artifact
// filter) and the legacy source_name (used to fall back when a
// deprecated / revoked record never got migrated to mitre-attack).
type bundleInfo struct {
	domain     string // "enterprise-attack" / "ics-attack" / "mobile-attack"
	sourceName string // "mitre-attack" / "mitre-ics-attack" / "mitre-mobile-attack"
}

// bundleOf returns the bundle identity implied by path's bundle
// subdirectory under root. The raw repo uses bare bundle names
// ("enterprise/", "mobile/", "ics/"), so we strip an optional
// "-attack" suffix to recover the bare name and then derive both
// fields from it. A zero-value return makes the artifact filter at
// Stage 1a reject the file (which is what we want when path doesn't
// live under a recognised bundle dir).
func bundleOf(root, path string) bundleInfo {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return bundleInfo{}
	}
	dir, _, ok := strings.Cut(rel, string(filepath.Separator))
	if !ok || dir == "" {
		return bundleInfo{}
	}
	bare := strings.TrimSuffix(dir, "-attack")
	switch bare {
	case "enterprise":
		// Enterprise dropped its "enterprise-" prefix when the
		// source_name was unified.
		return bundleInfo{domain: "enterprise-attack", sourceName: "mitre-attack"}
	case "ics", "mobile":
		return bundleInfo{
			domain:     fmt.Sprintf("%s-attack", bare),
			sourceName: fmt.Sprintf("mitre-%s-attack", bare),
		}
	default:
		return bundleInfo{}
	}
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

// deref returns *p when non-nil, otherwise the zero value of T. Stage
// 2 uses it to copy STIX optional fields (string / bool / time.Time
// pointers) into the canonical Attack record without repeating a nil
// guard at every call site.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
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

func externalID(refs []attack.ExternalReference, sourceName string) string {
	for _, r := range refs {
		if r.SourceName == sourceName && r.ExternalID != nil {
			return *r.ExternalID
		}
	}
	return ""
}
