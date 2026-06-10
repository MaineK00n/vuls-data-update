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

// primaryEntry collects everything we know about one ATT&CK primary
// object (any of the 11 kinds): the external ID, the kind, the parsed
// STIX struct (concrete type stored in raw via type assertion), and a
// JSONReader accumulating every raw file path contributing to this record.
type primaryEntry struct {
	extID  string
	kind   attackTypes.Kind
	raw    any
	reader *utiljson.JSONReader
}

// discovered is what Stage 1 records for every primary STIX object it
// finds during the discovery walk: just enough metadata for Stage 2 to
// decide which file to read into which concrete struct, and to skip
// extID collisions across enterprise / mobile / ics bundles.
type discovered struct {
	path     string
	uuid     string
	stixType string
	kind     attackTypes.Kind
	extID    string
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

// bidirRelatedEdges holds the forward and reverse projections of a
// STIX relationship whose both sides are []RelatedRef. Used for the
// four symmetric relations (mitigates, targets, detects,
// attributed-to). The `uses` relation can't share this shape because
// its sub-flavors mix RelatedRef / TechniqueUsed / Procedure values.
type bidirRelatedEdges struct {
	fwd map[string][]relatedrefTypes.RelatedRef
	rev map[string][]relatedrefTypes.RelatedRef
}

func newBidirRelatedEdges() bidirRelatedEdges {
	return bidirRelatedEdges{
		fwd: make(map[string][]relatedrefTypes.RelatedRef),
		rev: make(map[string][]relatedrefTypes.RelatedRef),
	}
}

// rels holds the relationship-derived data, keyed by primary external
// ID. Field names follow <ownerKind><OutputFieldName> so callers can
// see at a glance which kind owns the map and which Attack record
// field the slice feeds; symmetric forward+reverse relations live in a
// bidirRelatedEdges so the pair is named once.
type rels struct {
	// Technique-owned slices.
	techniqueParent        map[string]string                     // T → parent T extID (subtechnique-of forward, single)
	techniqueSubtechniques map[string][]string                   // T → child T extIDs (subtechnique-of reverse)
	techniqueTactics       map[string][]string                   // T → tactic shortnames (TA ID resolved at convert via tacticShortnameToID)
	techniqueProcedures    map[string][]procedureTypes.Procedure // T → G/S/C attacker procedures (reverse of all "uses" → T flavors)

	// "uses" relation (asymmetric flavors that can't share a bidir struct).
	groupTechniquesUsed    map[string][]techniqueusedTypes.TechniqueUsed // G → T (forward of uses G→T)
	softwareTechniquesUsed map[string][]techniqueusedTypes.TechniqueUsed // S → T (forward of uses S→T)
	campaignTechniquesUsed map[string][]techniqueusedTypes.TechniqueUsed // C → T (forward of uses C→T)
	groupSoftwaresUsed     map[string][]relatedrefTypes.RelatedRef       // G → S (forward of uses G→S)
	softwareGroupsUsing    map[string][]relatedrefTypes.RelatedRef       // S → G (reverse of uses G→S)
	campaignSoftwaresUsed  map[string][]relatedrefTypes.RelatedRef       // C → S (forward of uses C→S)
	softwareCampaignsUsing map[string][]relatedrefTypes.RelatedRef       // S → C (reverse of uses C→S)

	// Symmetric bidirectional []RelatedRef relations.
	mitigates    bidirRelatedEdges // fwd: M → T; rev: T → M
	targets      bidirRelatedEdges // fwd: T → A; rev: A → T
	detects      bidirRelatedEdges // fwd: DET → T; rev: T → DET
	attributedTo bidirRelatedEdges // fwd: C → G; rev: G → C

	// Tactic-owned reverse map (shortname → techniques).
	tacticTechniques map[string][]string

	// Pass-1.5 structural references resolved before Pass 2.
	detectionStrategyAnalytics map[string][]string // DET → analytic extIDs (x_mitre_analytic_refs)
	analyticDetectionStrategy  map[string]string   // analytic → owning DET extID (reverse)
	dataSourceComponents       map[string][]string // DS → data-component extIDs (reverse of x_mitre_data_source_ref)
	dataComponentSource        map[string]string   // DC → owning DS extID

	// shortname → Tactic external ID, used to fill TacticRef.ID when a
	// Technique lists its tactic shortnames.
	tacticShortnameToID map[string]string
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

	entries := make(map[string]*primaryEntry) // extID → entry
	uuidToExt := make(map[string]string)      // STIX UUID → ATT&CK external ID
	uuidKind := make(map[string]attackTypes.Kind)
	uuidToPath := make(map[string]string) // STIX UUID → absolute path

	// Stage 1 (discover): walk every STIX file and peek just enough
	// metadata (type / UUID / external_references) to classify it.
	// stixTypeToKind handles dispatch as data so an unrecognised STIX
	// type fails CI in one place; concrete unmarshalling and JSONReader
	// allocation are deferred to Stage 2 so skipped files (relationship,
	// identity, ...) don't pay for either.
	var primaries []discovered
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
		uuidToExt[peek.ID] = extID
		uuidKind[peek.ID] = kind
		uuidToPath[peek.ID] = path
		primaries = append(primaries, discovered{
			path:     path,
			uuid:     peek.ID,
			stixType: peek.Type,
			kind:     kind,
			extID:    extID,
		})
		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	// Stage 2 (build): per discovered primary, allocate a JSONReader
	// and read its concrete STIX struct. The first ext-ID occurrence
	// wins so a record published in multiple domain bundles
	// (enterprise/ics/mobile) collapses to one canonical entry.
	for _, p := range primaries {
		if _, exists := entries[p.extID]; exists {
			continue
		}
		r := utiljson.NewJSONReader()
		raw, err := readConcrete(p.stixType, p.path, args, r)
		if err != nil {
			return err
		}
		entries[p.extID] = &primaryEntry{extID: p.extID, kind: p.kind, raw: raw, reader: r}
	}

	idx := rels{
		techniqueParent:            make(map[string]string),
		techniqueSubtechniques:     make(map[string][]string),
		techniqueTactics:           make(map[string][]string),
		techniqueProcedures:        make(map[string][]procedureTypes.Procedure),
		groupTechniquesUsed:        make(map[string][]techniqueusedTypes.TechniqueUsed),
		softwareTechniquesUsed:     make(map[string][]techniqueusedTypes.TechniqueUsed),
		campaignTechniquesUsed:     make(map[string][]techniqueusedTypes.TechniqueUsed),
		groupSoftwaresUsed:         make(map[string][]relatedrefTypes.RelatedRef),
		softwareGroupsUsing:        make(map[string][]relatedrefTypes.RelatedRef),
		campaignSoftwaresUsed:      make(map[string][]relatedrefTypes.RelatedRef),
		softwareCampaignsUsing:     make(map[string][]relatedrefTypes.RelatedRef),
		mitigates:                  newBidirRelatedEdges(),
		targets:                    newBidirRelatedEdges(),
		detects:                    newBidirRelatedEdges(),
		attributedTo:               newBidirRelatedEdges(),
		tacticTechniques:           make(map[string][]string),
		detectionStrategyAnalytics: make(map[string][]string),
		analyticDetectionStrategy:  make(map[string]string),
		dataSourceComponents:       make(map[string][]string),
		dataComponentSource:        make(map[string]string),
		tacticShortnameToID:        make(map[string]string),
	}

	// Index Tactic shortnames → external IDs once so Pass 3 can fill
	// TacticRef.ID when a Technique lists its tactics by shortname.
	for _, entry := range entries {
		if entry.kind != attackTypes.KindTactic {
			continue
		}
		t := entry.raw.(*attack.XMitreTactic)
		if t.XMitreShortname != nil && *t.XMitreShortname != "" {
			idx.tacticShortnameToID[*t.XMitreShortname] = entry.extID
		}
	}

	// Pass 1.5: resolve UUID-based refs that aren't covered by relationships.
	//
	//   - Technique.TacticRefs → tactic shortname (and build tactic → techniques reverse)
	//   - DetectionStrategy.x_mitre_analytic_refs → analytic extIDs (forward + reverse)
	//   - DataComponent.x_mitre_data_source_ref → data-source extID (forward + reverse)
	//
	// Each reference Read also registers the cross-ref path against the
	// owning entry's reader for provenance.
	for _, entry := range entries {
		switch entry.kind {
		case attackTypes.KindTechnique:
			ap := entry.raw.(*attack.AttackPattern)
			// KillChainPhases shortnames (inline) → also reverse to tactic.Techniques
			for _, kc := range ap.KillChainPhases {
				switch kc.KillChainName {
				case "mitre-attack", "mitre-ics-attack", "mitre-mobile-attack":
					idx.techniqueTactics[entry.extID] = append(idx.techniqueTactics[entry.extID], kc.PhaseName)
					idx.tacticTechniques[kc.PhaseName] = append(idx.tacticTechniques[kc.PhaseName], entry.extID)
				}
			}
			// TacticRefs → x-mitre-tactic file → shortname
			for _, tr := range ap.TacticRefs {
				tacticPath, ok := uuidToPath[tr]
				if !ok {
					continue
				}
				var t attack.XMitreTactic
				if err := entry.reader.Read(tacticPath, args, &t); err != nil {
					return errors.Wrapf(err, "read tactic %s", tacticPath)
				}
				if t.XMitreShortname != nil {
					idx.techniqueTactics[entry.extID] = append(idx.techniqueTactics[entry.extID], *t.XMitreShortname)
					idx.tacticTechniques[*t.XMitreShortname] = append(idx.tacticTechniques[*t.XMitreShortname], entry.extID)
				}
			}
		case attackTypes.KindDetectStrategy:
			ds := entry.raw.(*attack.XMitreDetectionStrategy)
			for _, ar := range ds.XMitreAnalyticRefs {
				anExt, ok := uuidToExt[ar]
				if !ok {
					continue
				}
				idx.detectionStrategyAnalytics[entry.extID] = append(idx.detectionStrategyAnalytics[entry.extID], anExt)
				idx.analyticDetectionStrategy[anExt] = entry.extID
				if anPath, ok := uuidToPath[ar]; ok {
					if err := entry.reader.Read(anPath, args, new(attack.XMitreAnalytic)); err != nil {
						return errors.Wrapf(err, "read analytic %s", anPath)
					}
				}
			}
		case attackTypes.KindDataComponent:
			dc := entry.raw.(*attack.XMitreDataComponent)
			if dc.XMitreDataSourceRef != nil {
				if dsExt, ok := uuidToExt[*dc.XMitreDataSourceRef]; ok {
					idx.dataComponentSource[entry.extID] = dsExt
					idx.dataSourceComponents[dsExt] = append(idx.dataSourceComponents[dsExt], entry.extID)
					if dsPath, ok := uuidToPath[*dc.XMitreDataSourceRef]; ok {
						if err := entry.reader.Read(dsPath, args, new(attack.XMitreDataSource)); err != nil {
							return errors.Wrapf(err, "read data-source %s", dsPath)
						}
					}
				}
			}
		}
	}

	// Pass 2: read each domain's relationship files directly. Relationship
	// JSON only ever lives at <domain>/relationship/*.json, so a flat
	// per-directory ReadDir skips visiting every other STIX type folder
	// that Pass 1 already consumed.
	domains, err := os.ReadDir(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}
	for _, dom := range domains {
		if !dom.IsDir() || dom.Name() == ".git" {
			continue
		}
		relDir := filepath.Join(args, dom.Name(), "relationship")
		files, err := os.ReadDir(relDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return errors.Wrapf(err, "read %s", relDir)
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
				continue
			}
			path := filepath.Join(relDir, f.Name())

			var r attack.Relationship
			if err := utiljson.NewJSONReader().Read(path, args, &r); err != nil {
				return errors.Wrapf(err, "read json %s", path)
			}
			if r.RelationshipType == "" || r.SourceRef == "" || r.TargetRef == "" {
				continue
			}

			src, tgt := r.SourceRef, r.TargetRef
			srcKind, tgtKind := uuidKind[src], uuidKind[tgt]
			srcExt, tgtExt := uuidToExt[src], uuidToExt[tgt]
			desc := ""
			if r.Description != nil {
				desc = *r.Description
			}
			refs := toReferences(r.ExternalReferences)

			switch r.RelationshipType {
			case "subtechnique-of":
				// Forward: subtechnique points at a single parent
				// technique (the only edge whose forward projection
				// isn't a slice; handled inline).
				if srcEntry := entries[srcExt]; srcEntry != nil && tgtExt != "" {
					if err := attachRel(srcEntry, path, args); err != nil {
						return err
					}
					if err := attachCrossRef(srcEntry, uuidToPath[tgt], "attack-pattern", args); err != nil {
						return err
					}
					idx.techniqueParent[srcExt] = tgtExt
				}
				// Reverse: parent gets list of children.
				if err := recordEdge(idx.techniqueSubtechniques, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "attack-pattern", srcExt); err != nil {
					return err
				}
			case "mitigates":
				// fwd: M → T (mitigation's TechniquesMitigated).
				if err := recordEdge(idx.mitigates.fwd, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], "attack-pattern",
					relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs}); err != nil {
					return err
				}
				// rev: T → M (technique's Mitigations).
				if err := recordEdge(idx.mitigates.rev, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "course-of-action",
					relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs}); err != nil {
					return err
				}
			case "uses":
				if srcExt == "" || tgtExt == "" {
					continue
				}
				switch {
				case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindTechnique:
					if err := recordEdge(idx.groupTechniquesUsed, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], "attack-pattern",
						techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs}); err != nil {
						return err
					}
					if err := recordEdge(idx.techniqueProcedures, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "intrusion-set",
						procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs}); err != nil {
						return err
					}
				case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindSoftware:
					if err := recordEdge(idx.groupSoftwaresUsed, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], stixTypeFromUUID(tgt),
						relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs}); err != nil {
						return err
					}
					if err := recordEdge(idx.softwareGroupsUsing, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "intrusion-set",
						relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs}); err != nil {
						return err
					}
				case srcKind == attackTypes.KindSoftware && tgtKind == attackTypes.KindTechnique:
					if err := recordEdge(idx.softwareTechniquesUsed, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], "attack-pattern",
						techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs}); err != nil {
						return err
					}
					if err := recordEdge(idx.techniqueProcedures, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], stixTypeFromUUID(src),
						procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs}); err != nil {
						return err
					}
				case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindTechnique:
					if err := recordEdge(idx.campaignTechniquesUsed, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], "attack-pattern",
						techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs}); err != nil {
						return err
					}
					if err := recordEdge(idx.techniqueProcedures, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "campaign",
						procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs}); err != nil {
						return err
					}
				case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindSoftware:
					if err := recordEdge(idx.campaignSoftwaresUsed, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], stixTypeFromUUID(tgt),
						relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs}); err != nil {
						return err
					}
					if err := recordEdge(idx.softwareCampaignsUsing, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "campaign",
						relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs}); err != nil {
						return err
					}
				}
			case "attributed-to":
				if srcKind != attackTypes.KindCampaign || tgtKind != attackTypes.KindGroup || srcExt == "" || tgtExt == "" {
					break
				}
				// fwd: C → G (campaign's GroupsAttributed).
				if err := recordEdge(idx.attributedTo.fwd, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], "intrusion-set",
					relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs}); err != nil {
					return err
				}
				// rev: G → C (group's CampaignsAttributed).
				if err := recordEdge(idx.attributedTo.rev, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "campaign",
					relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs}); err != nil {
					return err
				}
			case "targets":
				// attack-pattern --targets--> x-mitre-asset
				if srcKind != attackTypes.KindTechnique || tgtKind != attackTypes.KindAsset || srcExt == "" || tgtExt == "" {
					break
				}
				// fwd: T → A (technique's AssetsTargeted).
				if err := recordEdge(idx.targets.fwd, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], "x-mitre-asset",
					relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs}); err != nil {
					return err
				}
				// rev: A → T (asset's TechniquesTargeting).
				if err := recordEdge(idx.targets.rev, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "attack-pattern",
					relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs}); err != nil {
					return err
				}
			case "detects":
				// x-mitre-detection-strategy --detects--> attack-pattern
				if srcKind != attackTypes.KindDetectStrategy || tgtKind != attackTypes.KindTechnique || srcExt == "" || tgtExt == "" {
					break
				}
				// fwd: DET → T (strategy's TechniquesDetected).
				if err := recordEdge(idx.detects.fwd, srcExt, tgtExt, entries[srcExt], path, args, uuidToPath[tgt], "attack-pattern",
					relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs}); err != nil {
					return err
				}
				// rev: T → DET (technique's DetectionStrategies).
				if err := recordEdge(idx.detects.rev, tgtExt, srcExt, entries[tgtExt], path, args, uuidToPath[src], "x-mitre-detection-strategy",
					relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs}); err != nil {
					return err
				}
			case "revoked-by":
				// Captured by the boolean Revoked field already; skip rel-level handling.
			}
		}
	}

	// Pass 3: convert each primary entry to the canonical record and emit.
	for _, entry := range entries {
		extracted := convert(entry, idx)
		outPath := filepath.Join(options.dir, "attack", fmt.Sprintf("%s.json", entry.extID))
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

// stixPeek is the minimal envelope Stage 1 decodes from every STIX
// file to classify it without paying for the full concrete struct.
type stixPeek struct {
	Type               string                     `json:"type"`
	ID                 string                     `json:"id"`
	ExternalReferences []attack.ExternalReference `json:"external_references"`
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

func attachRel(entry *primaryEntry, relPath, args string) error {
	if err := entry.reader.Read(relPath, args, new(attack.Relationship)); err != nil {
		return errors.Wrapf(err, "register relationship %s", relPath)
	}
	return nil
}

func attachCrossRef(entry *primaryEntry, crossPath, stixType, args string) error {
	if crossPath == "" {
		return nil
	}
	switch stixType {
	case "attack-pattern":
		return entry.reader.Read(crossPath, args, new(attack.AttackPattern))
	case "intrusion-set":
		return entry.reader.Read(crossPath, args, new(attack.IntrusionSet))
	case "malware":
		return entry.reader.Read(crossPath, args, new(attack.Malware))
	case "tool":
		return entry.reader.Read(crossPath, args, new(attack.Tool))
	case "course-of-action":
		return entry.reader.Read(crossPath, args, new(attack.CourseOfAction))
	case "campaign":
		return entry.reader.Read(crossPath, args, new(attack.Campaign))
	case "x-mitre-tactic":
		return entry.reader.Read(crossPath, args, new(attack.XMitreTactic))
	case "x-mitre-asset":
		return entry.reader.Read(crossPath, args, new(attack.XMitreAsset))
	case "x-mitre-detection-strategy":
		return entry.reader.Read(crossPath, args, new(attack.XMitreDetectionStrategy))
	case "x-mitre-analytic":
		return entry.reader.Read(crossPath, args, new(attack.XMitreAnalytic))
	case "x-mitre-data-source":
		return entry.reader.Read(crossPath, args, new(attack.XMitreDataSource))
	case "x-mitre-data-component":
		return entry.reader.Read(crossPath, args, new(attack.XMitreDataComponent))
	}
	return nil
}

// recordEdge attaches the relationship file + other-side STIX file to
// the owning entry's reader for provenance, then appends item into
// m[key]. A nil entry or empty other is a no-op so callers can apply
// the forward and reverse directions of a relationship symmetrically
// without an outer ok-check; entry is looked up by the caller via
// entries[key] and may legitimately be missing when the rel points at
// a STIX object outside the bundled dataset.
func recordEdge[T any](m map[string][]T, key, other string, entry *primaryEntry, relPath, args, otherPath, otherStixType string, item T) error {
	if entry == nil || other == "" {
		return nil
	}
	if err := attachRel(entry, relPath, args); err != nil {
		return err
	}
	if err := attachCrossRef(entry, otherPath, otherStixType, args); err != nil {
		return err
	}
	m[key] = append(m[key], item)
	return nil
}

func stixTypeFromUUID(uuid string) string {
	if idx := strings.Index(uuid, "--"); idx > 0 {
		return uuid[:idx]
	}
	return ""
}

func convert(entry *primaryEntry, idx rels) attackTypes.Attack {
	c := commonFromRaw(entry.raw)

	refs := make([]referenceTypes.Reference, 0, len(c.externalReferences))
	for _, er := range c.externalReferences {
		if er.URL == nil || *er.URL == "" {
			continue
		}
		refs = append(refs, referenceTypes.Reference{
			Source: er.SourceName,
			URL:    *er.URL,
		})
	}

	a := attackTypes.Attack{
		ID:          entry.extID,
		Kind:        entry.kind,
		Name:        c.name,
		Description: c.description,
		Domains:     slices.Clone(c.domains),
		Deprecated:  c.deprecated,
		Revoked:     c.revoked,
		Version:     c.version,
		Created:     c.created,
		Modified:    c.modified,
		References:  refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.MitreATTACK,
			Raws: entry.reader.Paths(),
		},
	}

	switch entry.kind {
	case attackTypes.KindTechnique:
		a.Technique = buildTechnique(entry.raw.(*attack.AttackPattern), entry.extID, idx)
	case attackTypes.KindTactic:
		a.Tactic = buildTactic(entry.raw.(*attack.XMitreTactic), idx)
	case attackTypes.KindMitigation:
		a.Mitigation = buildMitigation(entry.extID, idx)
	case attackTypes.KindGroup:
		a.Group = buildGroup(entry.raw.(*attack.IntrusionSet), entry.extID, idx)
	case attackTypes.KindSoftware:
		a.Software = buildSoftware(entry.raw, entry.extID, idx)
	case attackTypes.KindCampaign:
		a.Campaign = buildCampaign(entry.raw.(*attack.Campaign), entry.extID, idx)
	case attackTypes.KindAsset:
		a.Asset = buildAsset(entry.raw.(*attack.XMitreAsset), entry.extID, idx)
	case attackTypes.KindDetectStrategy:
		a.DetectionStrategy = buildDetectionStrategy(entry.extID, idx)
	case attackTypes.KindDataSource:
		a.AttackDataSource = buildAttackDataSource(entry.raw.(*attack.XMitreDataSource), entry.extID, idx)
	case attackTypes.KindDataComponent:
		a.DataComponent = buildDataComponent(entry.raw.(*attack.XMitreDataComponent), entry.extID, idx)
	case attackTypes.KindAnalytic:
		a.Analytic = buildAnalytic(entry.raw.(*attack.XMitreAnalytic), entry.extID, idx)
	}

	return a
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

func buildTechnique(ap *attack.AttackPattern, extID string, idx rels) techniqueTypes.Technique {
	isSub := derefBool(ap.XMitreIsSubtechnique)
	parent := ""
	if isSub {
		parent = idx.techniqueParent[extID]
	}

	tactics := make([]tacticrefTypes.TacticRef, 0, len(idx.techniqueTactics[extID]))
	for _, sn := range idx.techniqueTactics[extID] {
		tactics = append(tactics, tacticrefTypes.TacticRef{
			Shortname: sn,
			ID:        idx.tacticShortnameToID[sn],
		})
	}

	return techniqueTypes.Technique{
		Platforms:            slices.Clone(ap.XMitrePlatforms),
		Tactics:              tactics,
		IsSubtechnique:       isSub,
		Parent:               parent,
		Detection:            derefString(ap.XMitreDetection),
		DataSources:          slices.Clone(ap.XMitreDataSources),
		Mitigations:          idx.mitigates.rev[extID],
		Procedures:           idx.techniqueProcedures[extID],
		PermissionsRequired:  slices.Clone(ap.XMitrePermissionsRequired),
		EffectivePermissions: slices.Clone(ap.XMitreEffectivePermissions),
		DefenseBypassed:      slices.Clone(ap.XMitreDefenseBypassed),
		ImpactType:           slices.Clone(ap.XMitreImpactType),
		NetworkRequirements:  derefBool(ap.XMitreNetworkRequirements),
		RemoteSupport:        derefBool(ap.XMitreRemoteSupport),
		Subtechniques:        idx.techniqueSubtechniques[extID],
		AssetsTargeted:       idx.targets.fwd[extID],
		DetectionStrategies:  idx.detects.rev[extID],
	}
}

func buildTactic(t *attack.XMitreTactic, idx rels) tacticTypes.Tactic {
	shortname := derefString(t.XMitreShortname)
	return tacticTypes.Tactic{
		Shortname:  shortname,
		Techniques: idx.tacticTechniques[shortname],
	}
}

func buildMitigation(extID string, idx rels) mitigationTypes.Mitigation {
	return mitigationTypes.Mitigation{
		TechniquesMitigated: idx.mitigates.fwd[extID],
	}
}

func buildGroup(is *attack.IntrusionSet, extID string, idx rels) groupTypes.Group {
	return groupTypes.Group{
		Aliases:             mergeAliases(is.Aliases, is.XMitreAliases),
		TechniquesUsed:      idx.groupTechniquesUsed[extID],
		SoftwaresUsed:       idx.groupSoftwaresUsed[extID],
		CampaignsAttributed: idx.attributedTo.rev[extID],
	}
}

func buildSoftware(raw any, extID string, idx rels) softwareTypes.Software {
	var aliases, xAliases, platforms []string
	var stixType string
	switch s := raw.(type) {
	case *attack.Malware:
		stixType = "malware"
		aliases = s.Aliases
		xAliases = s.XMitreAliases
		platforms = s.XMitrePlatforms
	case *attack.Tool:
		stixType = "tool"
		aliases = s.Aliases
		xAliases = s.XMitreAliases
		platforms = s.XMitrePlatforms
	}
	return softwareTypes.Software{
		Type:           stixType,
		Aliases:        mergeAliases(aliases, xAliases),
		Platforms:      slices.Clone(platforms),
		TechniquesUsed: idx.softwareTechniquesUsed[extID],
		GroupsUsing:    idx.softwareGroupsUsing[extID],
		CampaignsUsing: idx.softwareCampaignsUsing[extID],
	}
}

func buildCampaign(camp *attack.Campaign, extID string, idx rels) campaignTypes.Campaign {
	return campaignTypes.Campaign{
		Aliases:          mergeAliases(camp.Aliases, nil),
		FirstSeen:        derefTime(camp.FirstSeen),
		LastSeen:         derefTime(camp.LastSeen),
		TechniquesUsed:   idx.campaignTechniquesUsed[extID],
		GroupsAttributed: idx.attributedTo.fwd[extID],
		SoftwaresUsed:    idx.campaignSoftwaresUsed[extID],
	}
}

func buildAsset(as *attack.XMitreAsset, extID string, idx rels) assetTypes.Asset {
	related := make([]assetTypes.RelatedAsset, 0, len(as.XMitreRelatedAssets))
	for _, ra := range as.XMitreRelatedAssets {
		related = append(related, assetTypes.RelatedAsset{
			Name:        ra.Name,
			Description: ra.Description,
			Sectors:     slices.Clone(ra.RelatedAssetSectors),
		})
	}
	return assetTypes.Asset{
		Platforms:           slices.Clone(as.XMitrePlatforms),
		Sectors:             slices.Clone(as.XMitreSectors),
		RelatedAssets:       related,
		TechniquesTargeting: idx.targets.rev[extID],
	}
}

func buildDetectionStrategy(extID string, idx rels) detectionstrategyTypes.DetectionStrategy {
	return detectionstrategyTypes.DetectionStrategy{
		Analytics:          idx.detectionStrategyAnalytics[extID],
		TechniquesDetected: idx.detects.fwd[extID],
	}
}

func buildAttackDataSource(ds *attack.XMitreDataSource, extID string, idx rels) datasourceTypes.DataSource {
	return datasourceTypes.DataSource{
		Platforms:        slices.Clone(ds.XMitrePlatforms),
		CollectionLayers: slices.Clone(ds.XMitreCollectionLayers),
		DataComponents:   idx.dataSourceComponents[extID],
	}
}

func buildDataComponent(dc *attack.XMitreDataComponent, extID string, idx rels) datacomponentTypes.DataComponent {
	logs := make([]datacomponentTypes.LogSource, 0, len(dc.XMitreLogSources))
	for _, ls := range dc.XMitreLogSources {
		logs = append(logs, datacomponentTypes.LogSource{Name: ls.Name, Channel: ls.Channel})
	}
	return datacomponentTypes.DataComponent{
		DataSource: idx.dataComponentSource[extID],
		LogSources: logs,
	}
}

func buildAnalytic(an *attack.XMitreAnalytic, extID string, idx rels) analyticTypes.Analytic {
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
	return analyticTypes.Analytic{
		DetectionStrategy:   idx.analyticDetectionStrategy[extID],
		Platforms:           slices.Clone(an.XMitrePlatforms),
		LogSourceReferences: lrefs,
		MutableElements:     mes,
	}
}

func derefTime(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
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
