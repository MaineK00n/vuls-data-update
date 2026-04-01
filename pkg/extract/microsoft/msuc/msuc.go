package msuc

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	windowskbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb"
	windowskbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb/supersededby"
	windowskbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb/update"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
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

	resChan := make(chan windowskbTypes.KB)
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
			filename := filepath.Join(o.dir, "windowskb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID))
			if _, err := os.Stat(filename); err == nil {
				f, err := os.Open(filename)
				if err != nil {
					return errors.Wrapf(err, "open %s", filename)
				}
				defer f.Close()

				var base windowskbTypes.KB
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

	return nil
}

func (e extractor) extract(path string, updateIDMap map[string]string) (windowskbTypes.KB, error) {
	var u msuc.Update
	if err := e.r.Read(path, e.baseDir, &u); err != nil {
		return windowskbTypes.KB{}, errors.Wrapf(err, "read %s", path)
	}

	if u.KBArticle == "" {
		return windowskbTypes.KB{}, errors.Errorf("KB article not found for update ID: %s", u.UpdateID)
	}

	ss := make([]windowskbSupersededByTypes.SupersededBy, 0, len(u.Supersededby))
	for _, s := range u.Supersededby {
		path, ok := updateIDMap[s.UpdateID]
		if !ok {
			return windowskbTypes.KB{}, errors.Errorf("path not found for update ID: %s", s.UpdateID)
		}

		var su msuc.Update
		if err := e.r.Read(path, e.baseDir, &su); err != nil {
			return windowskbTypes.KB{}, errors.Wrapf(err, "read %s", path)
		}

		if su.KBArticle == "" {
			return windowskbTypes.KB{}, errors.Errorf("KB article not found for update ID: %s", su.UpdateID)
		}

		ss = append(ss, windowskbSupersededByTypes.SupersededBy{
			UpdateID: su.UpdateID,
			KBID:     su.KBArticle,
		})
	}

	t, err := time.Parse("1/2/2006", u.LastModified)
	if err != nil {
		return windowskbTypes.KB{}, errors.Wrapf(err, "parse last modified %s", u.LastModified)
	}

	return windowskbTypes.KB{
		KBID: u.KBArticle,
		URL:  fmt.Sprintf("https://support.microsoft.com/help/%s", u.KBArticle),
		Updates: []windowskbUpdateTypes.Update{{
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
