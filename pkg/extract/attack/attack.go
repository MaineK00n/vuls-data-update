package attack

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	campaignTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/campaign"
	groupTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/group"
	procedureTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/procedure"
	softwareTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/software"
	tacticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/tactic"
	techniqueTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/technique"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
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

// stix represents the minimal set of STIX fields we need for extraction.
// The fetcher writes one JSON file per STIX object, which can be decoded
// into any of the domain Enterprise/ICS/Mobile structs (they are structurally
// compatible supersets). We use attack.Enterprise as the canonical form.
type stixObject = attack.Enterprise

// rels holds the relationship-derived maps populated in Pass 2.
type rels struct {
	subParent                map[string]string                              // technique UUID → parent technique UUID
	techMitigations          map[string][]string                            // technique UUID → mitigation UUIDs
	techProcedures           map[string][]procedureTypes.Procedure          // technique UUID → procedures
	groupTechniquesUsed      map[string][]techniqueusedTypes.TechniqueUsed  // group UUID → techniques used
	groupSoftwaresUsed       map[string][]string                            // group UUID → software ext IDs
	softwareTechniquesUsed   map[string][]techniqueusedTypes.TechniqueUsed  // software UUID → techniques used
	softwareGroupsUsing      map[string][]string                            // software UUID → group ext IDs
	campaignTechniquesUsed   map[string][]techniqueusedTypes.TechniqueUsed  // campaign UUID → techniques used
	campaignSoftwaresUsed    map[string][]string                            // campaign UUID → software ext IDs
	campaignGroupsAttributed map[string][]string                            // campaign UUID → group ext IDs
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

	// Pass 1: load every object, build UUID→ExternalID and UUID→Kind indexes.
	uuidToExt := make(map[string]string)
	uuidKind := make(map[string]attackTypes.Kind)
	tacticShortname := make(map[string]string) // tactic UUID → shortname
	objects := make([]stixObject, 0)
	r := utiljson.NewJSONReader()

	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		// directory structure: <args>/<domain>/<type>/<uuid>.json
		rel, err := filepath.Rel(args, path)
		if err != nil {
			return errors.Wrapf(err, "rel %s", path)
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 3 {
			return nil
		}

		var o stixObject
		if err := r.Read(path, args, &o); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}
		objects = append(objects, o)

		kind, ok := kindOf(o.Type)
		if !ok {
			return nil
		}
		if ext := externalID(o.ExternalReferences, "mitre-attack"); ext != "" {
			uuidToExt[o.ID] = ext
			uuidKind[o.ID] = kind
		}
		if o.Type == "x-mitre-tactic" && o.XMitreShortname != nil {
			tacticShortname[o.ID] = *o.XMitreShortname
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	// Pass 2: process relationship objects.
	relIndex := buildRels(objects, uuidToExt, uuidKind)

	// Pass 3: emit one Attack record per primary object.
	raws := r.Paths()
	emitted := make(map[string]bool) // external ID
	for _, o := range objects {
		kind, ok := uuidKind[o.ID]
		if !ok {
			continue
		}
		extID := uuidToExt[o.ID]
		if emitted[extID] {
			// de-dup across domains (same object may appear in enterprise and ics)
			continue
		}
		emitted[extID] = true

		extracted := convert(kind, extID, o, uuidToExt, tacticShortname, relIndex, raws)
		outPath := filepath.Join(options.dir, "attack", fmt.Sprintf("%s.json", extID))
		if err := util.Write(outPath, extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", outPath)
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.Attack,
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

func buildRels(objects []stixObject, uuidToExt map[string]string, uuidKind map[string]attackTypes.Kind) rels {
	idx := rels{
		subParent:                make(map[string]string),
		techMitigations:          make(map[string][]string),
		techProcedures:           make(map[string][]procedureTypes.Procedure),
		groupTechniquesUsed:      make(map[string][]techniqueusedTypes.TechniqueUsed),
		groupSoftwaresUsed:       make(map[string][]string),
		softwareTechniquesUsed:   make(map[string][]techniqueusedTypes.TechniqueUsed),
		softwareGroupsUsing:      make(map[string][]string),
		campaignTechniquesUsed:   make(map[string][]techniqueusedTypes.TechniqueUsed),
		campaignSoftwaresUsed:    make(map[string][]string),
		campaignGroupsAttributed: make(map[string][]string),
	}
	for _, o := range objects {
		if o.Type != "relationship" {
			continue
		}
		if o.RelationshipType == nil || o.SourceRef == nil || o.TargetRef == nil {
			continue
		}
		src, tgt := *o.SourceRef, *o.TargetRef
		desc := ""
		if o.Description != nil {
			desc = *o.Description
		}

		switch *o.RelationshipType {
		case "subtechnique-of":
			idx.subParent[src] = tgt
		case "mitigates":
			idx.techMitigations[tgt] = append(idx.techMitigations[tgt], src)
		case "uses":
			srcKind, tgtKind := uuidKind[src], uuidKind[tgt]
			srcExt, tgtExt := uuidToExt[src], uuidToExt[tgt]
			if srcExt == "" || tgtExt == "" {
				continue
			}
			switch {
			case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindTechnique:
				idx.groupTechniquesUsed[src] = append(idx.groupTechniquesUsed[src], techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc})
				idx.techProcedures[tgt] = append(idx.techProcedures[tgt], procedureTypes.Procedure{AttackerID: srcExt, Description: desc})
			case srcKind == attackTypes.KindGroup && tgtKind == attackTypes.KindSoftware:
				idx.groupSoftwaresUsed[src] = append(idx.groupSoftwaresUsed[src], tgtExt)
				idx.softwareGroupsUsing[tgt] = append(idx.softwareGroupsUsing[tgt], srcExt)
			case srcKind == attackTypes.KindSoftware && tgtKind == attackTypes.KindTechnique:
				idx.softwareTechniquesUsed[src] = append(idx.softwareTechniquesUsed[src], techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc})
				idx.techProcedures[tgt] = append(idx.techProcedures[tgt], procedureTypes.Procedure{AttackerID: srcExt, Description: desc})
			case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindTechnique:
				idx.campaignTechniquesUsed[src] = append(idx.campaignTechniquesUsed[src], techniqueusedTypes.TechniqueUsed{ID: tgtExt, Description: desc})
				idx.techProcedures[tgt] = append(idx.techProcedures[tgt], procedureTypes.Procedure{AttackerID: srcExt, Description: desc})
			case srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindSoftware:
				idx.campaignSoftwaresUsed[src] = append(idx.campaignSoftwaresUsed[src], tgtExt)
			}
		case "attributed-to":
			srcKind, tgtKind := uuidKind[src], uuidKind[tgt]
			tgtExt := uuidToExt[tgt]
			if tgtExt == "" {
				continue
			}
			if srcKind == attackTypes.KindCampaign && tgtKind == attackTypes.KindGroup {
				idx.campaignGroupsAttributed[src] = append(idx.campaignGroupsAttributed[src], tgtExt)
			}
		}
	}
	return idx
}

func convert(
	kind attackTypes.Kind,
	extID string,
	o stixObject,
	uuidToExt map[string]string,
	tacticShortname map[string]string,
	idx rels,
	raws []string,
) attackTypes.Attack {
	name := ""
	if o.Name != nil {
		name = *o.Name
	}
	desc := ""
	if o.Description != nil {
		desc = *o.Description
	}
	version := ""
	if o.XMitreVersion != nil {
		version = *o.XMitreVersion
	}
	deprecated := false
	if o.XMitreDeprecated != nil {
		deprecated = *o.XMitreDeprecated
	}
	revoked := false
	if o.Revoked != nil {
		revoked = *o.Revoked
	}

	refs := make([]referenceTypes.Reference, 0)
	for _, er := range o.ExternalReferences {
		url := ""
		if er.URL != nil {
			url = *er.URL
		}
		if url == "" || er.SourceName == "mitre-attack" {
			continue
		}
		refs = append(refs, referenceTypes.Reference{
			Source: er.SourceName,
			URL:    url,
		})
	}

	a := attackTypes.Attack{
		ID:          extID,
		Kind:        kind,
		Name:        name,
		Description: desc,
		Domains:     append([]string(nil), o.XMitreDomains...),
		Deprecated:  deprecated,
		Revoked:     revoked,
		Version:     version,
		Modified: func() time.Time {
			if o.Modified == nil {
				return time.Time{}
			}
			return *o.Modified
		}(),
		References: refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.Attack,
			Raws: raws,
		},
	}

	switch kind {
	case attackTypes.KindTechnique:
		a.Technique = buildTechnique(o, uuidToExt, tacticShortname, idx)
	case attackTypes.KindTactic:
		shortname := ""
		if o.XMitreShortname != nil {
			shortname = *o.XMitreShortname
		}
		a.Tactic = tacticTypes.Tactic{Shortname: shortname}
	case attackTypes.KindGroup:
		a.Group = groupTypes.Group{
			Aliases:        attackerAliases(o),
			TechniquesUsed: idx.groupTechniquesUsed[o.ID],
			SoftwaresUsed:  idx.groupSoftwaresUsed[o.ID],
		}
	case attackTypes.KindSoftware:
		a.Software = softwareTypes.Software{
			Type:           o.Type, // "malware" | "tool"
			Aliases:        attackerAliases(o),
			Platforms:      append([]string(nil), o.XMitrePlatforms...),
			TechniquesUsed: idx.softwareTechniquesUsed[o.ID],
			GroupsUsing:    idx.softwareGroupsUsing[o.ID],
		}
	case attackTypes.KindCampaign:
		a.Campaign = campaignTypes.Campaign{
			Aliases: attackerAliases(o),
			FirstSeen: func() time.Time {
				if o.FirstSeen == nil {
					return time.Time{}
				}
				return *o.FirstSeen
			}(),
			LastSeen: func() time.Time {
				if o.LastSeen == nil {
					return time.Time{}
				}
				return *o.LastSeen
			}(),
			TechniquesUsed:   idx.campaignTechniquesUsed[o.ID],
			GroupsAttributed: idx.campaignGroupsAttributed[o.ID],
			SoftwaresUsed:    idx.campaignSoftwaresUsed[o.ID],
		}
	}

	return a
}

func buildTechnique(o stixObject, uuidToExt map[string]string, tacticShortname map[string]string, idx rels) techniqueTypes.Technique {
	isSub := false
	if o.XMitreIsSubtechnique != nil {
		isSub = *o.XMitreIsSubtechnique
	}
	parent := ""
	if isSub {
		if pu, ok := idx.subParent[o.ID]; ok {
			parent = uuidToExt[pu]
		}
	}
	detection := ""
	if o.XMitreDetection != nil {
		detection = *o.XMitreDetection
	}
	networkReq := false
	if o.XMitreNetworkRequirements != nil {
		networkReq = *o.XMitreNetworkRequirements
	}
	remoteSupport := false
	if o.XMitreRemoteSupport != nil {
		remoteSupport = *o.XMitreRemoteSupport
	}

	mitigations := make([]string, 0, len(idx.techMitigations[o.ID]))
	for _, mu := range idx.techMitigations[o.ID] {
		if ext, ok := uuidToExt[mu]; ok {
			mitigations = append(mitigations, ext)
		}
	}

	tactics := make([]string, 0, len(o.KillChainPhases)+len(o.TacticRefs))
	for _, kc := range o.KillChainPhases {
		if kc.KillChainName == "mitre-attack" || kc.KillChainName == "mitre-ics-attack" || kc.KillChainName == "mitre-mobile-attack" {
			tactics = append(tactics, kc.PhaseName)
		}
	}
	for _, tr := range o.TacticRefs {
		if sn, ok := tacticShortname[tr]; ok {
			tactics = append(tactics, sn)
		}
	}

	return techniqueTypes.Technique{
		Platforms:            append([]string(nil), o.XMitrePlatforms...),
		Tactics:              tactics,
		IsSubtechnique:       isSub,
		Parent:               parent,
		Detection:            detection,
		DataSources:          append([]string(nil), o.XMitreDataSources...),
		Mitigations:          mitigations,
		Procedures:           idx.techProcedures[o.ID],
		PermissionsRequired:  append([]string(nil), o.XMitrePermissionsRequired...),
		EffectivePermissions: append([]string(nil), o.XMitreEffectivePermissions...),
		DefenseBypassed:      append([]string(nil), o.XMitreDefenseBypassed...),
		ImpactType:           append([]string(nil), o.XMitreImpactType...),
		NetworkRequirements:  networkReq,
		RemoteSupport:        remoteSupport,
	}
}

// attackerAliases collects unique aliases for Group/Software/Campaign objects,
// merging STIX `aliases` and Mitre `x_mitre_aliases`.
func attackerAliases(o stixObject) []string {
	seen := make(map[string]struct{}, len(o.Aliases)+len(o.XMitreAliases))
	out := make([]string, 0, len(o.Aliases)+len(o.XMitreAliases))
	for _, a := range o.Aliases {
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, a := range o.XMitreAliases {
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

func kindOf(stixType string) (attackTypes.Kind, bool) {
	switch stixType {
	case "attack-pattern":
		return attackTypes.KindTechnique, true
	case "x-mitre-tactic":
		return attackTypes.KindTactic, true
	case "course-of-action":
		return attackTypes.KindMitigation, true
	case "intrusion-set":
		return attackTypes.KindGroup, true
	case "malware", "tool":
		return attackTypes.KindSoftware, true
	case "campaign":
		return attackTypes.KindCampaign, true
	default:
		return "", false
	}
}

func externalID(refs []struct {
	Description *string `json:"description,omitempty"`
	ExternalID  *string `json:"external_id,omitempty"`
	SourceName  string  `json:"source_name"`
	URL         *string `json:"url,omitempty"`
}, sourceName string) string {
	for _, r := range refs {
		if r.SourceName == sourceName && r.ExternalID != nil {
			return *r.ExternalID
		}
	}
	return ""
}
