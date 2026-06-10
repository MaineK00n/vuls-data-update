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

	// Stage 1 builds the file list each ext-ID needs to produce its
	// canonical record and the few global maps Stage 2 has to consult
	// while parsing relationships. Nothing else crosses the
	// Stage 1 ↔ Stage 2 boundary.
	uuidToExt := make(map[string]string) // STIX UUID → ATT&CK external ID
	kindByExtID := make(map[string]attackTypes.Kind)
	stixTypeByExtID := make(map[string]string)
	peekByExtID := make(map[string]stixPeek) // first-occurrence peek, used for own cross-ref fields in Stage 2
	tacticShortnameToID := make(map[string]string)
	tacticUUIDToShortname := make(map[string]string)
	filesByExtID := make(map[string][]string)

	// Stage 1-internal helpers.
	uuidKind := make(map[string]attackTypes.Kind)
	uuidToPath := make(map[string]string)
	pathsByExtID := make(map[string][]string) // every bundle copy's file path, fanned out at Stage 1b/1c

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
		uuidToExt[peek.ID] = extID
		uuidKind[peek.ID] = kind
		uuidToPath[peek.ID] = path
		if _, exists := peekByExtID[extID]; !exists {
			peekByExtID[extID] = peek
			kindByExtID[extID] = kind
			stixTypeByExtID[extID] = peek.Type
		}
		if kind == attackTypes.KindTactic && peek.XMitreShortname != nil && *peek.XMitreShortname != "" {
			tacticShortnameToID[*peek.XMitreShortname] = extID
			tacticUUIDToShortname[peek.ID] = *peek.XMitreShortname
		}
		pathsByExtID[extID] = append(pathsByExtID[extID], path)
		filesByExtID[extID] = append(filesByExtID[extID], path)
		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	// Stage 1b: per-extID, link the files Stage 2 will need to build
	// the cross-ref fields. Forward refs (e.g. Technique → Tactic via
	// TacticRefs / KillChainPhases) and reverse refs (Tactic →
	// Techniques) both surface as file membership in filesByExtID, so
	// Stage 2 doesn't need a global edge index to know which files to
	// open.
	for extID := range kindByExtID {
		peek := peekByExtID[extID]
		switch kindByExtID[extID] {
		case attackTypes.KindTechnique:
			// KillChainPhases name the Tactic by its shortname; resolve
			// to the Tactic's ext-ID so we can add the Technique to that
			// Tactic's file list (for Tactic.Techniques reverse).
			for _, kc := range peek.KillChainPhases {
				switch kc.KillChainName {
				case "mitre-attack", "mitre-ics-attack", "mitre-mobile-attack":
					if tacticExt, ok := tacticShortnameToID[kc.PhaseName]; ok {
						for _, p := range pathsByExtID[extID] {
							filesByExtID[tacticExt] = append(filesByExtID[tacticExt], p)
						}
					}
				}
			}
			// TacticRefs point at Tactic UUIDs; pull the Tactic file in
			// for provenance + technique.Tactics ID resolution, and
			// pull the Technique's file into the Tactic for reverse.
			for _, tr := range peek.TacticRefs {
				tacticExt, ok := uuidToExt[tr]
				if !ok {
					continue
				}
				for _, p := range pathsByExtID[tacticExt] {
					filesByExtID[extID] = append(filesByExtID[extID], p)
				}
				for _, p := range pathsByExtID[extID] {
					filesByExtID[tacticExt] = append(filesByExtID[tacticExt], p)
				}
			}
		case attackTypes.KindDetectStrategy:
			for _, ar := range peek.XMitreAnalyticRefs {
				anExt, ok := uuidToExt[ar]
				if !ok {
					continue
				}
				for _, p := range pathsByExtID[anExt] {
					filesByExtID[extID] = append(filesByExtID[extID], p)
				}
				for _, p := range pathsByExtID[extID] {
					filesByExtID[anExt] = append(filesByExtID[anExt], p)
				}
			}
		case attackTypes.KindDataComponent:
			if peek.XMitreDataSourceRef == nil {
				continue
			}
			dsExt, ok := uuidToExt[*peek.XMitreDataSourceRef]
			if !ok {
				continue
			}
			for _, p := range pathsByExtID[dsExt] {
				filesByExtID[extID] = append(filesByExtID[extID], p)
			}
			for _, p := range pathsByExtID[extID] {
				filesByExtID[dsExt] = append(filesByExtID[dsExt], p)
			}
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
		entries, err := os.ReadDir(relDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return errors.Wrapf(err, "read %s", relDir)
		}
		for _, f := range entries {
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
			srcExt := uuidToExt[r.SourceRef]
			tgtExt := uuidToExt[r.TargetRef]
			if srcExt != "" {
				filesByExtID[srcExt] = append(filesByExtID[srcExt], path)
				for _, p := range pathsByExtID[tgtExt] {
					filesByExtID[srcExt] = append(filesByExtID[srcExt], p)
				}
			}
			if tgtExt != "" {
				filesByExtID[tgtExt] = append(filesByExtID[tgtExt], path)
				for _, p := range pathsByExtID[srcExt] {
					filesByExtID[tgtExt] = append(filesByExtID[tgtExt], p)
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
	for extID, files := range filesByExtID {
		kind := kindByExtID[extID]
		stixType := stixTypeByExtID[extID]
		ownPeek := peekByExtID[extID]
		selfPaths := pathsByExtID[extID]
		selfSet := make(map[string]bool, len(selfPaths))
		for _, p := range selfPaths {
			selfSet[p] = true
		}

		r := utiljson.NewJSONReader()
		var raw any
		domains := slices.Clone(ownPeek.XMitreDomains)
		domainSeen := make(map[string]bool, len(domains))
		for _, d := range domains {
			domainSeen[d] = true
		}

		// Per-entry rels: only this extID's slots get populated, but
		// the existing convert/build* helpers expect a `rels` so we
		// allocate one and fan the kind-specific accumulators back into
		// its maps.
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
			tacticShortnameToID:        tacticShortnameToID,
		}

		// Pre-fill the forward cross-refs from this entry's own peek.
		switch kind {
		case attackTypes.KindTechnique:
			for _, kc := range ownPeek.KillChainPhases {
				switch kc.KillChainName {
				case "mitre-attack", "mitre-ics-attack", "mitre-mobile-attack":
					idx.techniqueTactics[extID] = append(idx.techniqueTactics[extID], kc.PhaseName)
				}
			}
			for _, tr := range ownPeek.TacticRefs {
				if sn, ok := tacticUUIDToShortname[tr]; ok {
					idx.techniqueTactics[extID] = append(idx.techniqueTactics[extID], sn)
				}
			}
		case attackTypes.KindDetectStrategy:
			for _, ar := range ownPeek.XMitreAnalyticRefs {
				if anExt, ok := uuidToExt[ar]; ok {
					idx.detectionStrategyAnalytics[extID] = append(idx.detectionStrategyAnalytics[extID], anExt)
				}
			}
		case attackTypes.KindDataComponent:
			if ownPeek.XMitreDataSourceRef != nil {
				if dsExt, ok := uuidToExt[*ownPeek.XMitreDataSourceRef]; ok {
					idx.dataComponentSource[extID] = dsExt
				}
			}
		}

		seenFile := make(map[string]bool, len(files))
		for _, path := range files {
			if seenFile[path] {
				continue
			}
			seenFile[path] = true

			// Self primary file (or a cross-domain copy of it).
			if selfSet[path] {
				if raw == nil {
					var err error
					raw, err = readConcrete(stixType, path, args, r)
					if err != nil {
						return err
					}
				} else {
					if err := attachRead(stixType, path, args, r); err != nil {
						return errors.Wrapf(err, "attach self %s for %s", path, extID)
					}
					// Union x_mitre_domains from this bundle copy.
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
				}
				continue
			}

			// Peek to classify: relationship vs other-side primary.
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
				populateRelEdge(extID, kind, &rel, uuidToExt, uuidKind, &idx)
				continue
			}

			// Other-side primary file pulled in by cross-ref or
			// relationship's other side. Use the file's STIX type for
			// the read dispatch.
			if err := attachRead(fp.Type, path, args, r); err != nil {
				return errors.Wrapf(err, "attach %s for %s", path, extID)
			}
			otherExt := externalID(fp.ExternalReferences, "mitre-attack")
			if otherExt == "" {
				continue
			}
			populateCrossRefReverse(extID, kind, otherExt, kindByExtID[otherExt], &idx)
		}

		if raw == nil {
			// No primary file made it through — shouldn't happen if
			// Stage 1a wired everything correctly, but skip gracefully.
			continue
		}
		entry := primaryEntry{extID: extID, kind: kind, raw: raw, reader: r}
		extracted := convert(&entry, idx)
		extracted.Domains = slices.Clone(domains)
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

// populateRelEdge fills the per-entry rels slot corresponding to this
// extID's role (src or tgt) in the given relationship. Called once per
// relationship file in Stage 2; the entry's kind drives which slot is
// populated. Unknown relationship_type / kind combos are silently
// dropped — Stage 1c only routes files to relevant entries, so this
// path simply matches what Stage 1 already chose.
func populateRelEdge(extID string, kind attackTypes.Kind, rel *attack.Relationship, uuidToExt map[string]string, uuidKind map[string]attackTypes.Kind, idx *rels) {
	srcExt := uuidToExt[rel.SourceRef]
	tgtExt := uuidToExt[rel.TargetRef]
	srcKind := uuidKind[rel.SourceRef]
	tgtKind := uuidKind[rel.TargetRef]
	desc := ""
	if rel.Description != nil {
		desc = *rel.Description
	}
	refs := toReferences(rel.ExternalReferences)

	switch rel.RelationshipType {
	case "subtechnique-of":
		if kind != attackTypes.KindTechnique {
			return
		}
		if extID == srcExt && tgtExt != "" {
			idx.techniqueParent[extID] = tgtExt
		}
		if extID == tgtExt && srcExt != "" {
			idx.techniqueSubtechniques[extID] = append(idx.techniqueSubtechniques[extID], srcExt)
		}
	case "mitigates":
		if extID == srcExt && tgtExt != "" && kind == attackTypes.KindMitigation {
			idx.mitigates.fwd[extID] = append(idx.mitigates.fwd[extID], relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
		}
		if extID == tgtExt && srcExt != "" && kind == attackTypes.KindTechnique {
			idx.mitigates.rev[extID] = append(idx.mitigates.rev[extID], relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
		}
	case "uses":
		if srcExt == "" || tgtExt == "" {
			return
		}
		switch {
		case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindTechnique:
			if extID == srcExt && kind == attackTypes.KindGroup {
				idx.groupTechniquesUsed[extID] = append(idx.groupTechniquesUsed[extID], techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs})
			}
			if extID == tgtExt && kind == attackTypes.KindTechnique {
				idx.techniqueProcedures[extID] = append(idx.techniqueProcedures[extID], procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs})
			}
		case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindSoftware:
			if extID == srcExt && kind == attackTypes.KindGroup {
				idx.groupSoftwaresUsed[extID] = append(idx.groupSoftwaresUsed[extID], relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
			}
			if extID == tgtExt && kind == attackTypes.KindSoftware {
				idx.softwareGroupsUsing[extID] = append(idx.softwareGroupsUsing[extID], relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
			}
		case srcKind == attackTypes.KindSoftware && tgtKind == attackTypes.KindTechnique:
			if extID == srcExt && kind == attackTypes.KindSoftware {
				idx.softwareTechniquesUsed[extID] = append(idx.softwareTechniquesUsed[extID], techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs})
			}
			if extID == tgtExt && kind == attackTypes.KindTechnique {
				idx.techniqueProcedures[extID] = append(idx.techniqueProcedures[extID], procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs})
			}
		case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindTechnique:
			if extID == srcExt && kind == attackTypes.KindCampaign {
				idx.campaignTechniquesUsed[extID] = append(idx.campaignTechniquesUsed[extID], techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc, References: refs})
			}
			if extID == tgtExt && kind == attackTypes.KindTechnique {
				idx.techniqueProcedures[extID] = append(idx.techniqueProcedures[extID], procedureTypes.Procedure{AttackerID: srcExt, Description: desc, References: refs})
			}
		case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindSoftware:
			if extID == srcExt && kind == attackTypes.KindCampaign {
				idx.campaignSoftwaresUsed[extID] = append(idx.campaignSoftwaresUsed[extID], relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
			}
			if extID == tgtExt && kind == attackTypes.KindSoftware {
				idx.softwareCampaignsUsing[extID] = append(idx.softwareCampaignsUsing[extID], relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
			}
		}
	case "attributed-to":
		if srcKind != attackTypes.KindCampaign || tgtKind != attackTypes.KindGroup || srcExt == "" || tgtExt == "" {
			return
		}
		if extID == srcExt && kind == attackTypes.KindCampaign {
			idx.attributedTo.fwd[extID] = append(idx.attributedTo.fwd[extID], relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
		}
		if extID == tgtExt && kind == attackTypes.KindGroup {
			idx.attributedTo.rev[extID] = append(idx.attributedTo.rev[extID], relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
		}
	case "targets":
		if srcKind != attackTypes.KindTechnique || tgtKind != attackTypes.KindAsset || srcExt == "" || tgtExt == "" {
			return
		}
		if extID == srcExt && kind == attackTypes.KindTechnique {
			idx.targets.fwd[extID] = append(idx.targets.fwd[extID], relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
		}
		if extID == tgtExt && kind == attackTypes.KindAsset {
			idx.targets.rev[extID] = append(idx.targets.rev[extID], relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
		}
	case "detects":
		if srcKind != attackTypes.KindDetectStrategy || tgtKind != attackTypes.KindTechnique || srcExt == "" || tgtExt == "" {
			return
		}
		if extID == srcExt && kind == attackTypes.KindDetectStrategy {
			idx.detects.fwd[extID] = append(idx.detects.fwd[extID], relatedrefTypes.RelatedRef{ID: tgtExt, Description: desc, References: refs})
		}
		if extID == tgtExt && kind == attackTypes.KindTechnique {
			idx.detects.rev[extID] = append(idx.detects.rev[extID], relatedrefTypes.RelatedRef{ID: srcExt, Description: desc, References: refs})
		}
	}
}

// populateCrossRefReverse fills the reverse-direction cross-ref slot
// when Stage 2 sees another primary's file in this entry's list. The
// forward direction (Technique.Tactics from its own TacticRefs, etc.)
// is handled inline from the entry's own peek.
func populateCrossRefReverse(extID string, kind attackTypes.Kind, otherExt string, otherKind attackTypes.Kind, idx *rels) {
	switch kind {
	case attackTypes.KindTactic:
		// Other side is a Technique that lists this Tactic via
		// KillChainPhases or TacticRefs.
		if otherKind != attackTypes.KindTechnique {
			return
		}
		idx.tacticTechniques[extID] = append(idx.tacticTechniques[extID], otherExt)
	case attackTypes.KindAnalytic:
		// Other side is the DetectionStrategy that owns this Analytic.
		if otherKind != attackTypes.KindDetectStrategy {
			return
		}
		idx.analyticDetectionStrategy[extID] = otherExt
	case attackTypes.KindDataSource:
		// Other side is a DataComponent that names this DataSource.
		if otherKind != attackTypes.KindDataComponent {
			return
		}
		idx.dataSourceComponents[extID] = append(idx.dataSourceComponents[extID], otherExt)
	}
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
