package msuc

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	microsoftutil "github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/util"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	microsoftkbSupersedesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersedes"
	microsoftkbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/update"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/msuc"
)

type options struct {
	dir         string
	concurrency int
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "microsoft", "msuc"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft MSUC")

	uidm, err := buildUpdateIDMap(args)
	if err != nil {
		return errors.Wrapf(err, "build updateID to KB mapping")
	}

	if err := options.extract(args, uidm); err != nil {
		return errors.Wrapf(err, "extract")
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftMSUC,
		Name: new("Microsoft Update Catalog"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

func buildUpdateIDMap(root string) (map[string]string, error) {
	m := make(map[string]string)

	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var raw struct {
			UpdateID string `json:"update_id"`
		}
		if err := json.UnmarshalRead(f, &raw); err != nil {
			return errors.Wrapf(err, "unmarshal %s", path)
		}

		if raw.UpdateID == "" {
			return errors.Errorf("update ID not found in %s", path)
		}

		m[raw.UpdateID] = path

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	return m, nil
}

type extractor struct {
	baseDir string
	r       *utiljson.JSONReader
}

func (o options) extract(root string, updateIDMap map[string]string) error {
	eg, ctx := errgroup.WithContext(context.TODO())
	eg.SetLimit(1 + o.concurrency)

	reqChan := make(chan string)
	eg.Go(func() error {
		defer close(reqChan)

		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			if filepath.Ext(path) != ".json" {
				return nil
			}

			select {
			case reqChan <- path:
			case <-ctx.Done():
				return ctx.Err()
			}

			return nil
		})
	})

	resChan := make(chan microsoftkbTypes.KB)
	for i := 0; i < o.concurrency; i++ {
		eg.Go(func() error {
			for path := range reqChan {
				kb, err := (extractor{
					baseDir: root,
					r:       utiljson.NewJSONReader(),
				}).extract(path, updateIDMap)
				if err != nil {
					return errors.Wrapf(err, "extract %s", path)
				}

				select {
				case resChan <- kb:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}

	go func() {
		eg.Wait() //nolint:errcheck
		close(resChan)
	}()

	for kb := range resChan {
		if err := func() error {
			if len(kb.KBID) <= 3 {
				return errors.Errorf("unexpected KBID format. expected: len > 3, actual: %q", kb.KBID)
			}

			filename := filepath.Join(o.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID))
			if _, err := os.Stat(filename); err == nil {
				f, err := os.Open(filename)
				if err != nil {
					return errors.Wrapf(err, "open %s", filename)
				}
				defer f.Close()

				var base microsoftkbTypes.KB
				if err := json.UnmarshalRead(f, &base); err != nil {
					return errors.Wrapf(err, "decode %s", filename)
				}

				kb.Merge(base)
			}

			if err := util.Write(filename, kb, true); err != nil {
				return errors.Wrapf(err, "write %s", filename)
			}

			return nil
		}(); err != nil {
			return errors.Wrapf(err, "write %s", kb.KBID)
		}
	}

	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "wait for walk")
	}

	// Phase 2: read all written KB files, derive Supersedes, write all KB files back.
	kbDir := filepath.Join(o.dir, "microsoftkb")
	if _, err := os.Stat(kbDir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return errors.Wrapf(err, "stat %s", kbDir)
		}
		return nil
	}
	var kbs []microsoftkbTypes.KB
	if err := filepath.WalkDir(kbDir, func(path string, d fs.DirEntry, err error) error {
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

		var kb microsoftkbTypes.KB
		if err := json.UnmarshalRead(f, &kb); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		kbs = append(kbs, kb)
		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", kbDir)
	}

	microsoftutil.DeriveSupersedes(kbs)
	deriveCrossTrackSupersedes(kbs)

	for _, kb := range kbs {
		if err := util.Write(filepath.Join(o.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)), kb, true); err != nil {
			return errors.Wrapf(err, "write %s", kb.KBID)
		}
	}

	return nil
}

func (e extractor) extract(path string, updateIDMap map[string]string) (microsoftkbTypes.KB, error) {
	var u msuc.Update
	if err := e.r.Read(path, e.baseDir, &u); err != nil {
		return microsoftkbTypes.KB{}, errors.Wrapf(err, "read %s", path)
	}

	if u.KBArticle == "" {
		return microsoftkbTypes.KB{}, errors.Errorf("KB article not found for update ID: %s", u.UpdateID)
	}

	ss := make([]microsoftkbSupersededByTypes.SupersededBy, 0, len(u.Supersededby))
	for _, s := range u.Supersededby {
		path, ok := updateIDMap[s.UpdateID]
		if !ok {
			return microsoftkbTypes.KB{}, errors.Errorf("path not found for update ID: %s", s.UpdateID)
		}

		var su msuc.Update
		if err := e.r.Read(path, e.baseDir, &su); err != nil {
			return microsoftkbTypes.KB{}, errors.Wrapf(err, "read %s", path)
		}

		if su.KBArticle == "" {
			return microsoftkbTypes.KB{}, errors.Errorf("KB article not found for update ID: %s", su.UpdateID)
		}

		ss = append(ss, microsoftkbSupersededByTypes.SupersededBy{
			UpdateID: su.UpdateID,
			KBID:     su.KBArticle,
		})
	}

	t, err := time.Parse("1/2/2006", u.LastModified)
	if err != nil {
		return microsoftkbTypes.KB{}, errors.Wrapf(err, "parse last modified %s", u.LastModified)
	}

	return microsoftkbTypes.KB{
		KBID: u.KBArticle,
		URL:  fmt.Sprintf("https://support.microsoft.com/help/%s", u.KBArticle),
		Updates: []microsoftkbUpdateTypes.Update{{
			UpdateID:         u.UpdateID,
			Title:            u.Title,
			Description:      u.Description,
			SecurityBulletin: normalizeNA(u.SecurityBulliten),
			MSRCSeverity:     normalizeNA(u.MSRCSeverity),
			Architecture:     normalizeNA(u.Architecture),
			Classification:   u.Classification,
			Products: func() []string {
				switch s := normalizeNA(u.SupportedProducts); s {
				case "":
					return nil
				default:
					return strings.Split(s, ",")
				}
			}(),
			Languages: func() []string {
				switch s := normalizeNA(u.SupportedLanguages); s {
				case "":
					return nil
				default:
					return strings.Split(s, ",")
				}
			}(),
			MoreInfoURL:        u.MoreInfo,
			SupportURL:         u.SupportURL,
			SupersededBy:       ss,
			RebootBehavior:     normalizeNA(u.RebootBehavior),
			UserInput:          normalizeNA(u.UserInput),
			InstallationImpact: u.InstallationImpact,
			Connectivity:       normalizeNA(u.Connectivity),
			UninstallNotes:     normalizeNA(u.UninstallNotes),
			UninstallSteps:     normalizeNA(u.UninstallSteps),
			LastModified:       t,
			CatalogURL:         fmt.Sprintf("https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=%s", u.UpdateID),
		}},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.MicrosoftMSUC,
			Raws: e.r.Paths(),
		},
	}, nil
}

func normalizeNA(s string) string {
	if s == "n/a" {
		return ""
	}
	return s
}

// monthlyTrackTitleRE matches the title of a monthly Quality Update / Rollup,
// capturing year, month, track, and product name.
//
// Microsoft releases parallel-track updates per product per month:
//   - "Security Only Quality Update"        (narrowest)
//   - "Security Monthly Quality Rollup"     (includes Security Only + non-security fixes)
//   - "Preview of Monthly Quality Rollup"   (includes Security Monthly + next-month previews)
//   - "Cumulative Update"                   (Win10/11/Server 2016+)
//   - "Cumulative Update Preview"           (Win10/11/Server 2016+ preview track)
var monthlyTrackTitleRE = regexp.MustCompile(`^(\d{4})-(\d{2}) (Security Only Quality Update|Security Monthly Quality Rollup|Preview of Monthly Quality Rollup|Cumulative Update Preview|Cumulative Update) for (.+?) \(KB\d+\)$`)

// deriveCrossTrackSupersedes augments Update-level Supersedes / SupersededBy
// with cross-track equivalence for monthly Quality Rollups within the same
// product+year+month.
//
// Microsoft does NOT consistently record cross-track supersession in MSUC's
// per-Update SupersededBy graph: across the production raw corpus the SO/SM,
// SO/PV and SM/PV pairings are 0% covered while CU/CP is ~92% covered.
// However the broader-track update is functionally a superset of the narrower
// one, so for detection-time coverage we add synthetic edges (both
// Supersedes on the broader-track Update and the reverse SupersededBy on the
// narrower-track Update):
//
// Preview            ⊇ SecurityMonthly ⊇ SecurityOnly
// CumulativePreview  ⊇ Cumulative
//
// kbs is modified in place. Only Update-level edges are added: KB-level
// supersession is left to native KB-level signals (CVRF, Bulletin) so that
// cross-arch / partial supersession is not lossy-aggregated to KB level.
// Detection still discovers cross-track equivalence via the Update-level
// edges. Architecture pairing across tracks is 1:1 within a group because
// monthlyTrackTitleRE captures the architecture suffix (e.g. "for x64-based
// Systems") as part of the product key, so each (year, month,
// product+architecture, track) tuple has at most one Update.
//
// This is MSUC-specific: other Microsoft data sources either lack per-Update
// titles (CVRF, Bulletin) or do not expose modern monthly-track titles in the
// `YYYY-MM ...` form expected by monthlyTrackTitleRE (WSUSSCN2 uses the older
// "Month, YYYY" format for the relevant EOL products and omits Cumulative
// Update Preview entries entirely).
func deriveCrossTrackSupersedes(kbs []microsoftkbTypes.KB) {
	type track int
	const (
		trackUnknown track = iota
		trackSecurityOnly
		trackSecurityMonthly
		trackPreview
		trackCumulative
		trackCumulativePreview
	)

	classify := func(s string) track {
		switch s {
		case "Security Only Quality Update":
			return trackSecurityOnly
		case "Security Monthly Quality Rollup":
			return trackSecurityMonthly
		case "Preview of Monthly Quality Rollup":
			return trackPreview
		case "Cumulative Update":
			return trackCumulative
		case "Cumulative Update Preview":
			return trackCumulativePreview
		default:
			return trackUnknown
		}
	}

	type member struct{ kbID, updateID string }
	type group struct{ year, month, product string }
	grouped := make(map[group]map[track][]member)

	for _, kb := range kbs {
		for _, u := range kb.Updates {
			m := monthlyTrackTitleRE.FindStringSubmatch(u.Title)
			if m == nil {
				continue
			}
			tr := classify(m[3])
			if tr == trackUnknown {
				continue
			}
			g := group{year: m[1], month: m[2], product: microsoftutil.NormalizeProductName(m[4])}
			if grouped[g] == nil {
				grouped[g] = make(map[track][]member)
			}
			grouped[g][tr] = append(grouped[g][tr], member{kbID: kb.KBID, updateID: u.UpdateID})
		}
	}

	kbIdx := make(map[string]*microsoftkbTypes.KB, len(kbs))
	for i := range kbs {
		kbIdx[kbs[i].KBID] = &kbs[i]
	}
	updateIdx := func(kbID, updateID string) *microsoftkbUpdateTypes.Update {
		kb, ok := kbIdx[kbID]
		if !ok {
			return nil
		}
		if i := slices.IndexFunc(kb.Updates, func(u microsoftkbUpdateTypes.Update) bool {
			return u.UpdateID == updateID
		}); i >= 0 {
			return &kb.Updates[i]
		}
		return nil
	}

	addEdge := func(super, sub member) {
		if super.kbID == "" || sub.kbID == "" || super.kbID == sub.kbID {
			return
		}
		// Mirror DeriveSupersedes's Update-level guard: synthesize an edge
		// only when both endpoints have an UpdateID. updateIdx requires a
		// non-empty UpdateID to match deterministically.
		if super.updateID == "" || sub.updateID == "" {
			return
		}

		// Update-level edges only. Architecture pairing across tracks is 1:1
		// within the same (year, month, product+architecture) group because
		// the product capture in monthlyTrackTitleRE includes the architecture
		// suffix (e.g. "for x64-based Systems").
		if superU := updateIdx(super.kbID, super.updateID); superU != nil {
			if !slices.ContainsFunc(superU.Supersedes, func(s microsoftkbSupersedesTypes.Supersedes) bool {
				return s.KBID == sub.kbID && s.UpdateID == sub.updateID
			}) {
				superU.Supersedes = append(superU.Supersedes, microsoftkbSupersedesTypes.Supersedes{KBID: sub.kbID, UpdateID: sub.updateID})
			}
		}
		if subU := updateIdx(sub.kbID, sub.updateID); subU != nil {
			if !slices.ContainsFunc(subU.SupersededBy, func(s microsoftkbSupersededByTypes.SupersededBy) bool {
				return s.KBID == super.kbID && s.UpdateID == super.updateID
			}) {
				subU.SupersededBy = append(subU.SupersededBy, microsoftkbSupersededByTypes.SupersededBy{KBID: super.kbID, UpdateID: super.updateID})
			}
		}
	}

	addBetween := func(supers, subs []member) {
		for _, sup := range supers {
			for _, sub := range subs {
				addEdge(sup, sub)
			}
		}
	}

	inclusions := []struct{ super, sub track }{
		// Preview ⊇ SecurityMonthly ⊇ SecurityOnly.
		{trackPreview, trackSecurityMonthly},
		{trackPreview, trackSecurityOnly},
		{trackSecurityMonthly, trackSecurityOnly},
		// CumulativePreview ⊇ Cumulative.
		{trackCumulativePreview, trackCumulative},
	}
	for _, byTrack := range grouped {
		for _, inc := range inclusions {
			addBetween(byTrack[inc.super], byTrack[inc.sub])
		}
	}
}
