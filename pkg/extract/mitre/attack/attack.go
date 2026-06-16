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
	kindTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/kind"
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

// entryKey is the composite primary key used throughout Stage 1 and
// Stage 2. ATT&CK's external_id namespace is per-STIX-type rather than
// global: pre-2019 "1 Technique = 1 Mitigation" course-of-action records
// still carry the paired attack-pattern's T#### id (instead of the
// modern M#### prefix), so (Kind, ID) is the only key that is unique
// across the whole bundle set.
type entryKey struct {
	ext  string
	kind kindTypes.Kind
}

// entryInfo carries every per-(ext-ID, kind) detail Stage 2 needs to
// build one canonical record. Stage 1 populates a single
// map[entryKey]entryInfo instead of N parallel maps. Missing entries are
// expressed by a failed map lookup; the map never stores a zero value
// on purpose.
//
// The three path collections are kept separate so Stage 2 doesn't have
// to re-classify a single flat list:
//   - paths: this entry's own primary files (1..N bundle copies)
//   - rels:  relationship files this entry participates in, keyed by
//     STIX UUID so cross-bundle copies of the same logical
//     relationship dedupe naturally
//   - refs:  cross-referenced primary files (other side of relationships
//     or forward refs); raws-only, processed once each
type entryInfo struct {
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
	kind kindTypes.Kind
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
	entries := make(map[entryKey]entryInfo)
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
		var kind kindTypes.Kind
		switch peek.Type {
		case "relationship", "identity", "marking-definition", "x-mitre-collection", "x-mitre-matrix":
			return nil
		case "attack-pattern":
			kind = kindTypes.Technique
		case "x-mitre-tactic":
			kind = kindTypes.Tactic
		case "course-of-action":
			kind = kindTypes.Mitigation
		case "intrusion-set":
			kind = kindTypes.Group
		case "malware", "tool":
			kind = kindTypes.Software
		case "campaign":
			kind = kindTypes.Campaign
		case "x-mitre-asset":
			kind = kindTypes.Asset
		case "x-mitre-detection-strategy":
			kind = kindTypes.DetectStrategy
		case "x-mitre-analytic":
			kind = kindTypes.Analytic
		case "x-mitre-data-source":
			kind = kindTypes.DataSource
		case "x-mitre-data-component":
			kind = kindTypes.DataComponent
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
		// (Kind, ext-ID) is the composite primary key: pre-2019 "1
		// Technique = 1 Mitigation" course-of-action records still carry
		// their paired attack-pattern's T#### external_id, so keying
		// entries by ext alone collapses the deprecated stub onto its
		// live Technique. Composite key keeps both records — the live
		// Technique under {T####, KindTechnique} and the legacy stub
		// under {T####, KindMitigation} — without losing data or
		// double-linking into Stage 1b's tactic.refs.
		uuids[peek.ID] = uuidInfo{ext: extID, kind: kind, path: path}

		k := entryKey{ext: extID, kind: kind}
		e, ok := entries[k]
		if !ok {
			e = entryInfo{
				stixType: peek.Type,
				peek:     peek,
				rels:     make(map[string]string),
			}
		}
		e.paths = append(e.paths, path)
		entries[k] = e

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	// killChainDomain maps a kill_chain_phase's kill_chain_name to the
	// domain (x_mitre_domains value) of the Tactic that shortname
	// resolves under. ATT&CK reuses a handful of shortnames across
	// bundles (e.g. "initial-access" exists in Enterprise / ICS /
	// Mobile, each with a distinct TA* ID), so matching by shortname
	// alone is non-deterministic — Stage 1b and Stage 2 must also
	// filter the candidate Tactic by domain.
	killChainDomain := map[string]string{
		"mitre-attack":        "enterprise-attack",
		"mitre-ics-attack":    "ics-attack",
		"mitre-mobile-attack": "mobile-attack",
	}

	// tacticByDomainShortname keys every indexed Tactic by both its
	// declared domain(s) and its shortname so Stage 1b and Stage 2 can
	// resolve a KillChainPhase to the right Tactic in O(1) without
	// scanning entries (and without the cross-domain ambiguity that
	// shortname-only matching introduced). The value is the Tactic's
	// ext-ID; the corresponding entryKey is always {ext, KindTactic}.
	type tacticKey struct {
		domain    string
		shortname string
	}
	tacticByDomainShortname := make(map[tacticKey]string)
	for k, e := range entries {
		if k.kind != kindTypes.Tactic {
			continue
		}
		sn := e.peek.Tactic.XMitreShortname
		if sn == "" {
			continue
		}
		for _, d := range e.peek.XMitreDomains {
			tacticByDomainShortname[tacticKey{domain: d, shortname: sn}] = k.ext
		}
	}

	// Stage 1b: per-entry, link the files Stage 2 will need to build
	// the cross-ref fields. Forward refs (e.g. Technique → Tactic via
	// KillChainPhases) and reverse refs (Tactic → Techniques) both
	// surface as file membership in entries[k].refs, so Stage 2
	// doesn't need a global edge index to know which files to open.
	for k, e := range entries {
		switch k.kind {
		case kindTypes.Technique:
			// KillChainPhases name the Tactic by its shortname; resolve
			// to the right domain's Tactic via the prebuilt
			// (domain, shortname) → ext index so cross-bundle shortname
			// collisions (e.g. "initial-access" in both Enterprise and
			// Mobile) pick the matching Tactic deterministically.
			for _, kc := range e.peek.Technique.KillChainPhases {
				domain, ok := killChainDomain[kc.KillChainName]
				if !ok {
					return errors.Errorf("technique %s references kill_chain_phase with unknown kill_chain_name %q (expected one of mitre-attack, mitre-ics-attack, mitre-mobile-attack)", k.ext, kc.KillChainName)
				}
				tExt, ok := tacticByDomainShortname[tacticKey{domain: domain, shortname: kc.PhaseName}]
				if !ok {
					continue
				}
				tk := entryKey{ext: tExt, kind: kindTypes.Tactic}
				tac := entries[tk]
				tac.refs = append(tac.refs, e.paths...)
				entries[tk] = tac
			}
			entries[k] = e
		case kindTypes.DetectStrategy:
			for _, ar := range e.peek.DetectStrategy.XMitreAnalyticRefs {
				u, ok := uuids[ar]
				if !ok {
					continue
				}
				ak := entryKey{ext: u.ext, kind: u.kind}
				an, ok := entries[ak]
				if !ok {
					continue
				}
				e.refs = append(e.refs, an.paths...)
				an.refs = append(an.refs, e.paths...)
				entries[ak] = an
			}
			entries[k] = e
		case kindTypes.DataComponent:
			if e.peek.DataComponent.XMitreDataSourceRef == nil {
				continue
			}
			u, ok := uuids[*e.peek.DataComponent.XMitreDataSourceRef]
			if !ok {
				continue
			}
			dk := entryKey{ext: u.ext, kind: u.kind}
			ds, ok := entries[dk]
			if !ok {
				continue
			}
			e.refs = append(e.refs, ds.paths...)
			ds.refs = append(ds.refs, e.paths...)
			entries[dk] = ds
			entries[k] = e
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

			sk := entryKey{ext: uuids[r.SourceRef].ext, kind: uuids[r.SourceRef].kind}
			tk := entryKey{ext: uuids[r.TargetRef].ext, kind: uuids[r.TargetRef].kind}
			src, srcOK := entries[sk]
			tgt, tgtOK := entries[tk]
			if !srcOK || !tgtOK {
				return errors.Errorf("relationship %s references unindexed UUID (src=%s, tgt=%s)", path, r.SourceRef, r.TargetRef)
			}
			// MITRE distributes the same logical relationship in every
			// bundle that needs it (27 relationship UUIDs in the v18
			// enterprise/ics/mobile snapshot appear in two bundles).
			// The rels map dedupes on STIX UUID for Stage 2b, so only
			// fan out other-side paths into refs the first time we
			// see the id; otherwise we'd double-count tgt.paths into
			// src.refs (and vice versa), wasting Stage 2c r.Read work
			// and risking accumulator dups if a future Kind ever both
			// participates in a STIX relationship and reads e.refs.
			if _, seen := src.rels[r.ID]; !seen {
				src.refs = append(src.refs, tgt.paths...)
				tgt.refs = append(tgt.refs, src.paths...)
			}
			src.rels[r.ID] = path
			tgt.rels[r.ID] = path
			entries[sk] = src
			entries[tk] = tgt

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(args, dom, "relationship"))
		}
	}

	// Stage 2: for each unique (ext-ID, kind), walk its file list. Each
	// file is either this entry's primary (or a cross-domain copy of
	// it), a relationship file we parse for src/tgt direction + per-edge
	// content, or another primary's file pulled in by cross-ref. The
	// per-entry rels struct accumulates the kind-specific fields and
	// is then handed to convert() unchanged.
	for k, e := range entries {
		extID := k.ext
		r := utiljson.NewJSONReader()
		domains := slices.Clone(e.peek.XMitreDomains)

		// revokedBy collects the ext-IDs of the objects that replace
		// this entry when it is Revoked. Stage 2b appends one per
		// STIX revoked-by relationship pointing away from this entry;
		// typical records have at most one but a future split (e.g.
		// one Technique into several successors) can produce more.
		var revokedBy []string

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
		// directly. KillChainPhases resolve through the prebuilt
		// (domain, shortname) → ext index so the chosen Tactic always
		// matches the kill_chain_name's bundle, not whichever Tactic
		// with that shortname the map iteration happened to visit
		// first.
		switch k.kind {
		case kindTypes.Technique:
			for _, kc := range e.peek.Technique.KillChainPhases {
				domain, ok := killChainDomain[kc.KillChainName]
				if !ok {
					return errors.Errorf("technique %s references kill_chain_phase with unknown kill_chain_name %q (expected one of mitre-attack, mitre-ics-attack, mitre-mobile-attack)", extID, kc.KillChainName)
				}
				tacticExt, ok := tacticByDomainShortname[tacticKey{domain: domain, shortname: kc.PhaseName}]
				if !ok {
					return errors.Errorf("technique %s references kill_chain_phase {%s, %s} with no matching x-mitre-tactic", extID, kc.KillChainName, kc.PhaseName)
				}
				technique.tactics = append(technique.tactics, tacticrefTypes.TacticRef{Shortname: kc.PhaseName, ID: tacticExt})
			}
		case kindTypes.DetectStrategy:
			for _, ar := range e.peek.DetectStrategy.XMitreAnalyticRefs {
				if u, ok := uuids[ar]; ok {
					detectStrategy.analytics = append(detectStrategy.analytics, u.ext)
				}
			}
		case kindTypes.DataComponent:
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

			// Direction membership is decided on the full (Kind, ext)
			// composite key rather than ext alone. Bare ext equality
			// would mis-attribute on collisions like the pre-2019 1:1
			// course-of-action mitigations that reuse a Technique's
			// T#### id: a `mitigates` edge whose Technique target is
			// T1047 would also "look like" the legacy Mitigation
			// (Mitigation, T1047) under bare-ext matching, and a
			// future `revoked-by` chain on a colliding id would emit
			// a phantom RevokedBy on the wrong-kind sibling.
			isSrc := k.kind == src.kind && extID == src.ext
			isTgt := k.kind == tgt.kind && extID == tgt.ext

			// Stage 1c attaches every relationship to both endpoints'
			// rels maps, so the entry currently being processed must
			// be one of those endpoints. Anything else is a Stage 1
			// invariant violation.
			if !isSrc && !isTgt {
				return errors.Errorf("relationship %s reached entry %s/%s but matches neither src %s/%s nor tgt %s/%s", rel.ID, k.kind, extID, src.kind, src.ext, tgt.kind, tgt.ext)
			}

			switch rel.RelationshipType {
			case "subtechnique-of":
				if k.kind != kindTypes.Technique {
					return errors.Errorf("subtechnique-of relationship %s reached non-Technique endpoint %s (kind %v)", rel.ID, extID, k.kind)
				}
				if isSrc {
					technique.parent = tgt.ext
				}
				if isTgt {
					technique.subtechniques = append(technique.subtechniques, src.ext)
				}
			case "mitigates":
				if src.kind != kindTypes.Mitigation || tgt.kind != kindTypes.Technique {
					return errors.Errorf("mitigates relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if isSrc {
					mitigation.techniquesMitigated = append(mitigation.techniquesMitigated, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if isTgt {
					technique.mitigations = append(technique.mitigations, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "uses":
				switch {
				case src.kind == kindTypes.Group && tgt.kind == kindTypes.Technique:
					if isSrc {
						group.techniquesUsed = append(group.techniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgt.ext, Description: desc, References: refs})
					}
					if isTgt {
						technique.procedures = append(technique.procedures, procedureTypes.Procedure{AttackerKind: src.kind, AttackerID: src.ext, Description: desc, References: refs})
					}
				case src.kind == kindTypes.Group && tgt.kind == kindTypes.Software:
					if isSrc {
						group.softwaresUsed = append(group.softwaresUsed, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
					}
					if isTgt {
						software.groupsUsing = append(software.groupsUsing, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
					}
				case src.kind == kindTypes.Software && tgt.kind == kindTypes.Technique:
					if isSrc {
						software.techniquesUsed = append(software.techniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgt.ext, Description: desc, References: refs})
					}
					if isTgt {
						technique.procedures = append(technique.procedures, procedureTypes.Procedure{AttackerKind: src.kind, AttackerID: src.ext, Description: desc, References: refs})
					}
				case src.kind == kindTypes.Campaign && tgt.kind == kindTypes.Technique:
					if isSrc {
						campaign.techniquesUsed = append(campaign.techniquesUsed, techniqueusedTypes.TechniqueUsed{ID: tgt.ext, Description: desc, References: refs})
					}
					if isTgt {
						technique.procedures = append(technique.procedures, procedureTypes.Procedure{AttackerKind: src.kind, AttackerID: src.ext, Description: desc, References: refs})
					}
				case src.kind == kindTypes.Campaign && tgt.kind == kindTypes.Software:
					if isSrc {
						campaign.softwaresUsed = append(campaign.softwaresUsed, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
					}
					if isTgt {
						software.campaignsUsing = append(software.campaignsUsing, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
					}
				default:
					return errors.Errorf("uses relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
			case "attributed-to":
				if src.kind != kindTypes.Campaign || tgt.kind != kindTypes.Group {
					return errors.Errorf("attributed-to relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if isSrc {
					campaign.groupsAttributed = append(campaign.groupsAttributed, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if isTgt {
					group.campaignsAttributed = append(group.campaignsAttributed, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "targets":
				if src.kind != kindTypes.Technique || tgt.kind != kindTypes.Asset {
					return errors.Errorf("targets relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if isSrc {
					technique.assetsTargeted = append(technique.assetsTargeted, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if isTgt {
					asset.techniquesTargeting = append(asset.techniquesTargeting, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "detects":
				if src.kind != kindTypes.DetectStrategy || tgt.kind != kindTypes.Technique {
					return errors.Errorf("detects relationship %s has unexpected endpoints: src kind=%v, tgt kind=%v", rel.ID, src.kind, tgt.kind)
				}
				if isSrc {
					detectStrategy.techniquesDetected = append(detectStrategy.techniquesDetected, relatedrefTypes.RelatedRef{ID: tgt.ext, Description: desc, References: refs})
				}
				if isTgt {
					technique.detectionStrategies = append(technique.detectionStrategies, relatedrefTypes.RelatedRef{ID: src.ext, Description: desc, References: refs})
				}
			case "revoked-by":
				// MITRE points a withdrawn object at its replacement
				// via revoked-by. Record the replacement on the
				// source side so the canonical Attack record can
				// surface "use X instead" alongside the Revoked
				// flag. The target side (the replacement) doesn't
				// need to know what it replaced.
				if isSrc {
					revokedBy = append(revokedBy, tgt.ext)
				}
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
			// uuids carries kind alongside ext for free, so we read
			// the cross-ref's kind directly from the Stage 1 UUID
			// index rather than re-consulting entries. With the
			// composite-key entries map, an entries[ext] lookup
			// alone is no longer well-defined (e.g. T1047 has both
			// a Technique and a legacy Mitigation entry).
			u := uuids[fp.ID]
			if u.ext == "" {
				return errors.Errorf("file %s (id %s) was not indexed in Stage 1 but is referenced from %s", path, fp.ID, extID)
			}
			switch k.kind {
			case kindTypes.Tactic:
				if u.kind == kindTypes.Technique {
					tactic.techniques = append(tactic.techniques, u.ext)
				}
			case kindTypes.Analytic:
				if u.kind == kindTypes.DetectStrategy {
					analytic.detectionStrategy = u.ext
				}
			case kindTypes.DataSource:
				if u.kind == kindTypes.DataComponent {
					dataSource.components = append(dataSource.components, u.ext)
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
		switch k.kind {
		case kindTypes.Technique:
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
				Kind:        k.kind,
				Name:        deref(ap.Name),
				Description: deref(ap.Description),
				Domains:     domains,
				Deprecated:  deref(ap.XMitreDeprecated),
				Revoked:     deref(ap.Revoked),
				RevokedBy:   revokedBy,
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
		case kindTypes.Tactic:
			var t attack.XMitreTactic
			if err := r.Read(e.paths[0], args, &t); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        k.kind,
				Name:        deref(t.Name),
				Description: deref(t.Description),
				Domains:     domains,
				Deprecated:  deref(t.XMitreDeprecated),
				Revoked:     deref(t.Revoked),
				RevokedBy:   revokedBy,
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
		case kindTypes.Mitigation:
			var m attack.CourseOfAction
			if err := r.Read(e.paths[0], args, &m); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        k.kind,
				Name:        deref(m.Name),
				Description: deref(m.Description),
				Domains:     domains,
				Deprecated:  deref(m.XMitreDeprecated),
				Revoked:     deref(m.Revoked),
				RevokedBy:   revokedBy,
				Version:     deref(m.XMitreVersion),
				Created:     m.Created,
				Modified:    m.Modified,
				References:  toReferences(m.ExternalReferences),
				DataSource:  sourceTypes.Source{ID: sourceTypes.MitreATTACK, Raws: r.Paths()},
				Mitigation: mitigationTypes.Mitigation{
					TechniquesMitigated: mitigation.techniquesMitigated,
				},
			}
		case kindTypes.Group:
			var is attack.IntrusionSet
			if err := r.Read(e.paths[0], args, &is); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        k.kind,
				Name:        deref(is.Name),
				Description: deref(is.Description),
				Domains:     domains,
				Deprecated:  deref(is.XMitreDeprecated),
				Revoked:     deref(is.Revoked),
				RevokedBy:   revokedBy,
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
		case kindTypes.Software:
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
					Kind:        k.kind,
					Name:        deref(m.Name),
					Description: deref(m.Description),
					Domains:     domains,
					Deprecated:  deref(m.XMitreDeprecated),
					Revoked:     deref(m.Revoked),
					RevokedBy:   revokedBy,
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
					Kind:        k.kind,
					Name:        deref(t.Name),
					Description: deref(t.Description),
					Domains:     domains,
					Deprecated:  deref(t.XMitreDeprecated),
					Revoked:     deref(t.Revoked),
					RevokedBy:   revokedBy,
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
		case kindTypes.Campaign:
			var camp attack.Campaign
			if err := r.Read(e.paths[0], args, &camp); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        k.kind,
				Name:        deref(camp.Name),
				Description: deref(camp.Description),
				Domains:     domains,
				Deprecated:  deref(camp.XMitreDeprecated),
				Revoked:     deref(camp.Revoked),
				RevokedBy:   revokedBy,
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
		case kindTypes.Asset:
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
				Kind:        k.kind,
				Name:        deref(as.Name),
				Description: deref(as.Description),
				Domains:     domains,
				Deprecated:  deref(as.XMitreDeprecated),
				Revoked:     deref(as.Revoked),
				RevokedBy:   revokedBy,
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
		case kindTypes.DetectStrategy:
			var ds attack.XMitreDetectionStrategy
			if err := r.Read(e.paths[0], args, &ds); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:   extID,
				Kind: k.kind,
				Name: deref(ds.Name),
				// XMitreDetectionStrategy has no description field.
				Domains:    domains,
				Deprecated: deref(ds.XMitreDeprecated),
				Revoked:    deref(ds.Revoked),
				RevokedBy:  revokedBy,
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
		case kindTypes.DataSource:
			var ds attack.XMitreDataSource
			if err := r.Read(e.paths[0], args, &ds); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			extracted = attackTypes.Attack{
				ID:          extID,
				Kind:        k.kind,
				Name:        deref(ds.Name),
				Description: deref(ds.Description),
				Domains:     domains,
				Deprecated:  deref(ds.XMitreDeprecated),
				Revoked:     deref(ds.Revoked),
				RevokedBy:   revokedBy,
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
		case kindTypes.DataComponent:
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
				Kind:        k.kind,
				Name:        deref(dc.Name),
				Description: deref(dc.Description),
				Domains:     domains,
				Deprecated:  deref(dc.XMitreDeprecated),
				Revoked:     deref(dc.Revoked),
				RevokedBy:   revokedBy,
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
		case kindTypes.Analytic:
			var an attack.XMitreAnalytic
			if err := r.Read(e.paths[0], args, &an); err != nil {
				return errors.Wrapf(err, "read self %s for %s", e.paths[0], extID)
			}
			lrefs := make([]analyticTypes.LogSourceReference, 0, len(an.XMitreLogSourceReferences))
			for _, lr := range an.XMitreLogSourceReferences {
				// x_mitre_data_component_ref is a STIX UUID; the
				// canonical record expects the DataComponent's DC*
				// ext-ID. Unlike its sibling forward-ref fields
				// (DataComponent.DataSource, DetectionStrategy.Analytics,
				// Analytic.DetectionStrategy — all omitempty) the
				// LogSourceReference.DataComponent JSON tag carries
				// no omitempty, so the schema treats it as required.
				// An unindexed UUID here is MITRE schema drift CI
				// should surface, not a recoverable miss.
				u, ok := uuids[lr.XMitreDataComponentRef]
				if !ok || u.ext == "" {
					return errors.Errorf("analytic %s log_source_reference points at unindexed data-component UUID %q", extID, lr.XMitreDataComponentRef)
				}
				lrefs = append(lrefs, analyticTypes.LogSourceReference{
					DataComponent: u.ext,
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
				Kind:        k.kind,
				Name:        deref(an.Name),
				Description: deref(an.Description),
				Domains:     domains,
				Deprecated:  deref(an.XMitreDeprecated),
				Revoked:     deref(an.Revoked),
				RevokedBy:   revokedBy,
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
			return errors.Errorf("unexpected kind for %s: %s", extID, k.kind)
		}

		// Per-kind subdirectory namespaces the ext-ID so kinds that
		// happen to share an external_id (pre-2019 1:1 mitigation stub
		// vs. its live Technique) coexist as distinct records.
		if err := util.Write(filepath.Join(options.dir, "attack", string(k.kind), fmt.Sprintf("%s.json", extID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "attack", string(k.kind), fmt.Sprintf("%s.json", extID)))
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

// bundleOf identifies which ATT&CK bundle a file belongs to from its
// first path component. The expected input layout is the one produced
// by vuls-data-raw-mitre-attack: bare bundle directory names
// (enterprise / ics / mobile). Stage 1c iterates the same fixed list,
// so the two stages agree on what they will accept. Files outside
// those three directories return the zero bundleInfo and are dropped
// by the Stage 1a distribution-artifact filter.
func bundleOf(root, path string) bundleInfo {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return bundleInfo{}
	}
	dir, _, ok := strings.Cut(rel, string(filepath.Separator))
	if !ok || dir == "" {
		return bundleInfo{}
	}
	switch dir {
	case "enterprise":
		// Enterprise dropped its "enterprise-" prefix when the
		// source_name was unified.
		return bundleInfo{domain: "enterprise-attack", sourceName: "mitre-attack"}
	case "ics", "mobile":
		return bundleInfo{
			domain:     fmt.Sprintf("%s-attack", dir),
			sourceName: fmt.Sprintf("mitre-%s-attack", dir),
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
