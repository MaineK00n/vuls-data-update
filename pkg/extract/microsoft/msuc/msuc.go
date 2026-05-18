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

// monthlyTrackTitleRE matches the modern title of a monthly Quality Update /
// Rollup ("YYYY-MM ..."), capturing year, month, track, and product name.
//
// Microsoft releases parallel-track updates per product per month:
//   - "Security Only Quality Update"        (narrowest)
//   - "Security Monthly Quality Rollup"     (includes Security Only + non-security fixes)
//   - "Preview of Monthly Quality Rollup"   (includes Security Monthly + next-month previews)
//   - "Cumulative Update"                   (Win10/11/Server 2016+)
//   - "Cumulative Update Preview"           (Win10/11/Server 2016+ preview track)
var monthlyTrackTitleRE = regexp.MustCompile(`^(\d{4})-(\d{2}) (Security Only Quality Update|Security Monthly Quality Rollup|Preview of Monthly Quality Rollup|Cumulative Update Preview|Cumulative Update) for (.+?) \(KB\d+\)$`)

// monthlyTrackTitleOldRE matches the older title format used by 2016 - mid 2017
// monthly updates ("Month, YYYY ...") for Win7 / Server 2008 R2 / Server 2012 /
// Server 2012 R2 / Win 8.1 era KBs. The month appears as an English name
// BEFORE the year (e.g. "April, 2017 ..."), so the capture order differs from
// monthlyTrackTitleRE:
//   m[1] = month name (e.g. "April")     -- vs. m[1] = year ("2017") in modern
//   m[2] = year       (e.g. "2017")      -- vs. m[2] = month ("04") in modern
//   m[3] = track                         -- same as modern
//   m[4] = product                       -- same as modern
//
// Whitespace is intentionally strict (a single ASCII space at every
// boundary). In a snapshot of the production raw MSUC corpus taken
// 2026-05 (150 old-format titles), every title used exactly one space
// at each separator, with zero observed variants (no double-space /
// no missing space / no tab). A title that ever fails this strict
// shape will be silently skipped by parseMSUCUpdateGroup and
// surface as a visible drop in synthesised cross-track edges, at
// which point the regex can be loosened with empirical justification.
var monthlyTrackTitleOldRE = regexp.MustCompile(`^(January|February|March|April|May|June|July|August|September|October|November|December), (\d{4}) (Security Only Quality Update|Security Monthly Quality Rollup|Preview of Monthly Quality Rollup|Cumulative Update Preview|Cumulative Update) for (.+?) \(KB\d+\)$`)

// ieCumTitleModernRE matches the modern MSUC title for an Internet Explorer
// cumulative security update ("YYYY-MM Cumulative Security Update for Internet
// Explorer N for <OS-arch> (KBxxxxx)"). The YYYY-MM prefix first appears in
// 2017-04 alongside the older un-prefixed format and the two coexist through
// 2018-08; from 2018-09 onward Microsoft uses this modern format
// consistently. Targets the legacy OS releases Microsoft kept issuing IE
// updates for (Win 7, Win 8.1, Embedded 7, Server 2008 R2 / 2012 / 2012 R2).
// The "Cumulative " prefix is occasionally omitted on out-of-band releases.
var ieCumTitleModernRE = regexp.MustCompile(`^(\d{4})-(\d{2}) (?:Cumulative )?Security Update for Internet Explorer \d+(?: Service Pack \d+)? for (.+?) \(KB\d+\)$`)

// ieCumTitleOldRE matches the older MSUC title format used during the
// Bulletin era and the post-Bulletin transition (2003-11 through 2018-08):
// "(Cumulative )?Security Update for Internet Explorer N for <OS-arch>
// (KBxxxxx)". No date is embedded in the title, so the calendar month is
// taken from the ieCumOldReleaseMonth static map below, keyed by the KBID
// captured by the second group. Capturing KBID this way avoids depending on
// u.LastModified (which is the catalog page's "Last Updated" field — not a
// release timestamp).
var ieCumTitleOldRE = regexp.MustCompile(`^(?:Cumulative )?Security Update for Internet Explorer \d+(?: Service Pack \d+)? for (.+?) \(KB(\d+)\)$`)

// ieCumOldReleaseMonth maps an IE cumulative KB ID to the calendar month
// (YYYY-MM) when Microsoft first released that update. Used by the old-format
// IE Cum parser entry below — see ieCumTitleOldRE for the title shape.
//
// The map covers the full era during which Microsoft published IE cumulative
// updates without embedding YYYY-MM in the catalog title (2003-11 → 2018-08):
//
//   - Bulletin era (≤ 2017-03): release month taken verbatim from each
//     Microsoft Security Bulletin's date_posted field — the authoritative
//     source while Bulletins were being published.
//   - Post-Bulletin transition (2017-04 → 2018-08): the old un-prefixed
//     title and the new "YYYY-MM ..." title coexist; for the un-prefixed
//     entries the release month is taken from the catalog page's "Last
//     Updated" field at scrape time. From 2018-09 onward Microsoft uses
//     the modern "YYYY-MM <title>" convention consistently, so this
//     transition era is closed; no further KBs need to be added unless
//     Microsoft ever re-releases an old IE cumulative.
//
// Because both eras are frozen (Bulletin retired April 2017, modern format
// fully adopted from 2018-09), this map is deterministic and exhaustive for
// every IE cumulative KB whose MSUC title lacks a YYYY-MM prefix.
var ieCumOldReleaseMonth = map[string]string{
	"824145":  "2003-11",
	"832894":  "2004-02",
	"834707":  "2004-10",
	"867801":  "2004-07",
	"883939":  "2005-06",
	"889293":  "2004-12",
	"890923":  "2005-02",
	"896688":  "2005-11",
	"896727":  "2005-08",
	"905915":  "2005-12",
	"910620":  "2006-02",
	"912812":  "2006-04",
	"916281":  "2006-06",
	"918899":  "2006-08",
	"922760":  "2006-11",
	"928090":  "2007-02",
	"931768":  "2007-05",
	"933566":  "2007-06",
	"937143":  "2007-08",
	"939653":  "2007-10",
	"942615":  "2007-12",
	"944533":  "2008-02",
	"947864":  "2008-04",
	"950759":  "2008-06",
	"953838":  "2008-08",
	"956390":  "2008-10",
	"958215":  "2008-12",
	"960714":  "2008-12",
	"961260":  "2009-02",
	"963027":  "2009-04",
	"969897":  "2009-06",
	"972260":  "2009-07",
	"974455":  "2009-10",
	"976325":  "2009-12",
	"978207":  "2010-01",
	"980182":  "2010-03",
	"982381":  "2010-06",
	"2183461": "2010-08",
	"2360131": "2010-10",
	"2416400": "2010-12",
	"2482017": "2011-02",
	"2497640": "2011-04",
	"2530548": "2011-06",
	"2559049": "2011-08",
	"2586448": "2011-10",
	"2618444": "2011-12",
	"2647516": "2012-02",
	"2675157": "2012-04",
	"2699988": "2012-06",
	"2719177": "2012-07",
	"2722913": "2012-08",
	"2744842": "2012-09",
	"2761451": "2012-11",
	"2761465": "2012-12",
	"2792100": "2013-02",
	"2799329": "2013-01",
	"2809289": "2013-03",
	"2817183": "2013-04",
	"2829530": "2013-05",
	"2838727": "2013-06",
	"2846071": "2013-07",
	"2847204": "2013-05",
	"2850869": "2013-08",
	"2862772": "2013-08",
	"2870699": "2013-09",
	"2879017": "2013-10",
	"2884101": "2013-10",
	"2888505": "2013-11",
	"2898785": "2013-12",
	"2909921": "2014-02",
	"2920753": "2015-11",
	"2920788": "2015-11",
	"2920791": "2015-11",
	"2920810": "2015-11",
	"2925418": "2014-03",
	"2936068": "2014-04",
	"2953522": "2014-05",
	"2956058": "2015-11",
	"2956066": "2015-11",
	"2956070": "2015-11",
	"2956073": "2015-11",
	"2956081": "2015-11",
	"2956092": "2015-11",
	"2956097": "2015-11",
	"2956098": "2015-11",
	"2956099": "2015-11",
	"2957689": "2014-06",
	"2961851": "2014-05",
	"2962872": "2014-07",
	"2963950": "2014-06",
	"2963952": "2014-07",
	"2964358": "2014-05",
	"2964444": "2014-05",
	"2976627": "2014-08",
	"2977629": "2014-09",
	"2987107": "2014-10",
	"3003057": "2014-11",
	"3008923": "2014-12",
	"3021952": "2015-02",
	"3032359": "2015-03",
	"3034196": "2015-02",
	"3038314": "2015-04",
	"3049563": "2015-05",
	"3058515": "2015-06",
	"3065822": "2015-07",
	"3078071": "2015-08",
	"3081444": "2015-08",
	"3087038": "2015-09",
	"3087985": "2015-08",
	"3093983": "2015-10",
	"3097617": "2015-10",
	"3100773": "2015-11",
	"3104002": "2015-12",
	"3105211": "2015-11",
	"3105213": "2015-11",
	"3116869": "2015-12",
	"3116900": "2015-12",
	"3124263": "2016-01",
	"3124266": "2016-01",
	"3124275": "2016-01",
	"3134814": "2016-02",
	"3135173": "2016-02",
	"3135174": "2016-02",
	"3139929": "2016-03",
	"3140745": "2016-03",
	"3140768": "2016-03",
	"3147458": "2016-04",
	"3147461": "2016-04",
	"3148198": "2016-04",
	"3154070": "2016-05",
	"3156387": "2016-05",
	"3156421": "2016-05",
	"3160005": "2016-06",
	"3163017": "2016-06",
	"3163018": "2016-06",
	"3163912": "2016-07",
	"3170106": "2016-07",
	"3172985": "2016-07",
	"3175443": "2016-08",
	"3176492": "2016-08",
	"3176493": "2016-08",
	"3176495": "2016-08",
	"3185319": "2016-09",
	"3185331": "2016-10",
	"3185611": "2016-09",
	"3185614": "2016-09",
	"3189866": "2016-09",
	"3191492": "2016-10",
	"3192391": "2016-10",
	"3192392": "2016-10",
	"3192393": "2016-10",
	"3192440": "2016-10",
	"3192441": "2016-10",
	"3194798": "2016-10",
	"3197655": "2016-11",
	"3197867": "2016-11",
	"3197873": "2016-11",
	"3197874": "2016-11",
	"3197876": "2016-11",
	"3198585": "2016-11",
	"3198586": "2016-11",
	"3200970": "2016-11",
	"3203621": "2016-12",
	"3205383": "2016-12",
	"3205386": "2016-12",
	"3205394": "2016-12",
	"3205400": "2016-12",
	"3205401": "2016-12",
	"3205408": "2016-12",
	"3206632": "2016-12",
	"3208481": "2016-12",
	"3218362": "2017-03",
	"4012204": "2017-03",
	"4012216": "2017-03",
	"4012606": "2017-03",
	"4013198": "2017-03",
	"4013429": "2017-03",
	"4014661": "2017-04",
	"4018271": "2017-05",
	"4021558": "2017-06",
	"4025252": "2017-07",
	"4034733": "2017-08",
	"4036586": "2017-09",
	"4040685": "2017-10",
	"4047206": "2017-11",
	"4052978": "2017-12",
	"4056568": "2018-01",
	"4074736": "2018-02",
	"4089187": "2018-03",
	"4092946": "2018-04",
	"4096040": "2018-03",
	"4103768": "2018-05",
	"4230450": "2018-06",
	"4339093": "2018-07",
	"4343205": "2018-08",
}

// msucUpdateGroupParsers lists the title formats recognised by
// parseMSUCUpdateGroup, tried in order. A regex match claims the title for
// that parser — later parsers are not tried even if extract fails, since
// the entries are ordered (modern → old) so a regex match is a definite
// "this title belongs to this parser's class".
//
// layout is passed to time.Parse together with the dateStr built by
// extract; this is the single source of truth for normalising every
// recognised date shape to the same (year, month) tuple. trackStr is the
// canonical phrase classify expects — most entries return the verbatim
// Microsoft label (e.g. "Security Monthly Quality Rollup"), but a parser
// may normalise several title variants onto one canonical phrase (e.g.
// ieCumTitleModernRE collapses both "Security Update for Internet
// Explorer" and "Cumulative Security Update for Internet Explorer" into a
// single trackStr "Cumulative Security Update for Internet Explorer").
// extract may return ok=false to signal that the title matched the regex
// but the entry-specific date resolution failed (e.g. the old IE Cum KB
// ID is not in ieCumOldReleaseMonth); parseMSUCUpdateGroup then reports
// ok=false without trying later parsers. Adding a new title format only
// needs a new entry here.
var msucUpdateGroupParsers = []struct {
	re      *regexp.Regexp
	layout  string
	extract func(m []string) (dateStr, trackStr, product string, ok bool)
}{
	{
		re:     monthlyTrackTitleRE,
		layout: "2006-01",
		extract: func(m []string) (string, string, string, bool) {
			return fmt.Sprintf("%s-%s", m[1], m[2]), m[3], m[4], true
		},
	},
	{
		re:     monthlyTrackTitleOldRE,
		layout: "January, 2006",
		extract: func(m []string) (string, string, string, bool) {
			return fmt.Sprintf("%s, %s", m[1], m[2]), m[3], m[4], true
		},
	},
	{
		re:     ieCumTitleModernRE,
		layout: "2006-01",
		extract: func(m []string) (string, string, string, bool) {
			return fmt.Sprintf("%s-%s", m[1], m[2]), "Cumulative Security Update for Internet Explorer", m[3], true
		},
	},
	{
		re:     ieCumTitleOldRE,
		layout: "2006-01",
		extract: func(m []string) (string, string, string, bool) {
			ym, ok := ieCumOldReleaseMonth[m[2]]
			if !ok {
				return "", "", "", false
			}
			return ym, "Cumulative Security Update for Internet Explorer", m[1], true
		},
	},
}

// parseMSUCUpdateGroup parses an MSUC Update into its (year, month, track,
// product) tuple. year/month are normalised through time.Parse, so every
// recognised title shape (modern "YYYY-MM ..." MR, older "Month, YYYY ..."
// MR, modern IE Cum, and old IE Cum with date drawn from
// ieCumOldReleaseMonth) produces the same group key. ok is false when the
// title matches no known format, when the matching entry's extract function
// fails (e.g. old IE Cum KB ID is not in the map), or when the dateStr fails
// time.Parse validation (e.g. malformed month "13" in a title-embedded date).
func parseMSUCUpdateGroup(u microsoftkbUpdateTypes.Update) (year, month, trackStr, product string, ok bool) {
	for _, p := range msucUpdateGroupParsers {
		m := p.re.FindStringSubmatch(u.Title)
		if m == nil {
			continue
		}
		dateStr, track, prod, ok := p.extract(m)
		if !ok {
			return "", "", "", "", false
		}
		t, err := time.Parse(p.layout, dateStr)
		if err != nil {
			slog.Warn("skip MSUC title with invalid year/month", "title", u.Title, "err", err)
			return "", "", "", "", false
		}
		return fmt.Sprintf("%04d", t.Year()), fmt.Sprintf("%02d", int(t.Month())), track, prod, true
	}
	return "", "", "", "", false
}

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
// Preview / SecurityMonthly ⊇ IECumulative
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
// titles (CVRF, Bulletin) or only expose titles via fields the MSUC-flavoured
// regexes here are not tuned for. Title formats recognised here:
//   - modern "YYYY-MM ..." via monthlyTrackTitleRE
//   - older "Month, YYYY ..." via monthlyTrackTitleOldRE (2016 - mid 2017
//     Win7 / Server 2008 R2 / Server 2012 / Server 2012 R2 / Win 8.1)
//   - IE cumulative "YYYY-MM (Cumulative )?Security Update for Internet
//     Explorer N for <OS-arch> (KB...)" via ieCumTitleModernRE
//   - IE cumulative "(Cumulative )?Security Update for Internet Explorer N for
//     <OS-arch> (KB...)" via ieCumTitleOldRE (date from ieCumOldReleaseMonth)
func deriveCrossTrackSupersedes(kbs []microsoftkbTypes.KB) {
	type track int
	const (
		trackUnknown track = iota
		trackSecurityOnly
		trackSecurityMonthly
		trackPreview
		trackCumulative
		trackCumulativePreview
		trackIECumulative
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
		case "Cumulative Security Update for Internet Explorer":
			return trackIECumulative
		default:
			return trackUnknown
		}
	}

	type member struct{ kbID, updateID string }
	type group struct{ year, month, product string }
	grouped := make(map[group]map[track][]member)

	for _, kb := range kbs {
		for _, u := range kb.Updates {
			year, month, trackStr, product, ok := parseMSUCUpdateGroup(u)
			if !ok {
				continue
			}
			tr := classify(trackStr)
			if tr == trackUnknown {
				continue
			}
			g := group{year: year, month: month, product: microsoftutil.NormalizeProductName(product)}
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
		// Preview ⊇ SecurityMonthly ⊇ IECumulative.
		//
		// Microsoft's same-month Monthly Quality Rollup for legacy OS releases
		// (Win 7 / Win 8.1 / Embedded 7 / Server 2008 R2 / 2012 / 2012 R2)
		// includes the same-month IE cumulative update for that OS, but the
		// MSUC per-Update SupersededBy graph never publishes this link. Add
		// synthetic edges so that detection-time coverage walks reach IE Cum
		// KBs via an applied MR/Preview update. (SecurityOnly does NOT include
		// IE updates and is therefore intentionally not paired.)
		{trackSecurityMonthly, trackIECumulative},
		{trackPreview, trackIECumulative},
	}
	for _, byTrack := range grouped {
		for _, inc := range inclusions {
			addBetween(byTrack[inc.super], byTrack[inc.sub])
		}
	}
}
