package attack

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	fetchAttack "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/attack"
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
// compatible supersets). We use fetchAttack.Enterprise as the canonical form.
type stixObject = fetchAttack.Enterprise

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

	// Pass 1: load every object, build UUID→ExternalID index for techniques and tactics.
	uuidToExt := make(map[string]string)
	tacticShortname := make(map[string]string) // tactic UUID → shortname
	objects := make([]stixObject, 0)
	readerPaths := make(map[string][]string) // keyed by UUID of primary record (attack-pattern, tactic, course-of-action)
	r := utiljson.NewJSONReader()

	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		// skip non-object files (e.g. datasource.json if present)
		if filepath.Base(path) == "datasource.json" {
			return nil
		}
		// directory structure: <args>/<domain>/<type>/<uuid>.json
		rel, err := filepath.Rel(args, path)
		if err != nil {
			return err
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

		switch o.Type {
		case "attack-pattern", "x-mitre-tactic", "course-of-action":
			if ext := externalID(o.ExternalReferences, "mitre-attack"); ext != "" {
				uuidToExt[o.ID] = ext
				readerPaths[o.ID] = []string{rel}
			}
			if o.Type == "x-mitre-tactic" && o.XMitreShortname != nil {
				tacticShortname[o.ID] = *o.XMitreShortname
			}
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	// Pass 2: build subtechnique parent map from relationship objects.
	subParent := make(map[string]string) // child UUID → parent UUID
	for _, o := range objects {
		if o.Type != "relationship" {
			continue
		}
		if o.RelationshipType == nil || *o.RelationshipType != "subtechnique-of" {
			continue
		}
		if o.SourceRef == nil || o.TargetRef == nil {
			continue
		}
		subParent[*o.SourceRef] = *o.TargetRef
	}

	// Pass 3: emit one Attack record per attack-pattern / x-mitre-tactic / course-of-action.
	raws := r.Paths()
	emitted := make(map[string]bool) // external ID
	for _, o := range objects {
		kind, ok := kindOf(o.Type)
		if !ok {
			continue
		}
		extID := uuidToExt[o.ID]
		if extID == "" {
			continue
		}
		if emitted[extID] {
			// de-dup across domains (same technique may appear in enterprise and ics)
			continue
		}
		emitted[extID] = true

		extracted := convert(kind, extID, o, uuidToExt, tacticShortname, subParent, raws)
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

func convert(
	kind attackTypes.Kind,
	extID string,
	o stixObject,
	uuidToExt map[string]string,
	tacticShortname map[string]string,
	subParent map[string]string,
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
	shortname := ""
	if o.XMitreShortname != nil {
		shortname = *o.XMitreShortname
	}
	isSub := false
	if o.XMitreIsSubtechnique != nil {
		isSub = *o.XMitreIsSubtechnique
	}
	deprecated := false
	if o.XMitreDeprecated != nil {
		deprecated = *o.XMitreDeprecated
	}
	revoked := false
	if o.Revoked != nil {
		revoked = *o.Revoked
	}

	parent := ""
	if isSub {
		if pu, ok := subParent[o.ID]; ok {
			parent = uuidToExt[pu]
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

	platforms := append([]string(nil), o.XMitrePlatforms...)
	domains := append([]string(nil), o.XMitreDomains...)

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

	return attackTypes.Attack{
		ID:             extID,
		Kind:           kind,
		Name:           name,
		Description:    desc,
		Domains:        domains,
		Platforms:      platforms,
		Tactics:        tactics,
		Shortname:      shortname,
		IsSubtechnique: isSub,
		Parent:         parent,
		Deprecated:     deprecated,
		Revoked:        revoked,
		Version:        version,
		Modified:       o.Modified,
		References:     refs,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.Attack,
			Raws: raws,
		},
	}
}

func kindOf(stixType string) (attackTypes.Kind, bool) {
	switch stixType {
	case "attack-pattern":
		return attackTypes.KindTechnique, true
	case "x-mitre-tactic":
		return attackTypes.KindTactic, true
	case "course-of-action":
		return attackTypes.KindMitigation, true
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

