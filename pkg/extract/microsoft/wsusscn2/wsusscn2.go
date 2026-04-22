package wsusscn2

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	microsoftutil "github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/util"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	microsoftkbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/update"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/wsusscn2"
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

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "wsusscn2"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft WSUSSCN2")
	if err := options.extract(args); err != nil {
		return errors.Wrapf(err, "extract")
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftWSUSSCN2,
		Name: new("Microsoft WSUSSCN2"),
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

type extractor struct {
	baseDir string
	r       *utiljson.JSONReader
}

func (o options) extract(root string) error {
	revIDToUpdateID, err := buildRevIDtoUpdateID(root)
	if err != nil {
		return errors.Wrapf(err, "build revisionID to updateID mapping")
	}

	if err := filepath.WalkDir(filepath.Join(root, "u"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		kb, err := (extractor{
			baseDir: root,
			r:       utiljson.NewJSONReader(),
		}).extract(path, revIDToUpdateID)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}
		if kb == nil {
			return nil
		}

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

		if err := util.Write(filename, *kb, true); err != nil {
			return errors.Wrapf(err, "write %s", filename)
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", filepath.Join(root, "u"))
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

	for _, kb := range kbs {
		if err := util.Write(filepath.Join(o.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)), kb, true); err != nil {
			return errors.Wrapf(err, "write %s", kb.KBID)
		}
	}

	return nil
}

func buildRevIDtoUpdateID(root string) (map[string]string, error) {
	m := make(map[string]string)
	if err := filepath.WalkDir(filepath.Join(root, "u"), func(path string, d fs.DirEntry, err error) error {
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

		var u wsusscn2.Update
		if err := json.UnmarshalRead(f, &u); err != nil {
			return errors.Wrapf(err, "unmarshal %s", path)
		}

		if u.RevisionID == "" {
			return errors.Errorf("revision ID not found in %s", path)
		}

		if u.UpdateID == "" {
			return errors.Errorf("update ID not found in %s", path)
		}

		m[u.RevisionID] = u.UpdateID

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", filepath.Join(root, "u"))
	}

	return m, nil
}

func (e extractor) extract(path string, revIDToUpdateID map[string]string) (*microsoftkbTypes.KB, error) {
	var rawU wsusscn2.Update
	if err := e.r.Read(path, e.baseDir, &rawU); err != nil {
		return nil, errors.Wrapf(err, "read %s", path)
	}

	if rawU.IsBundle != "true" {
		return nil, nil
	}

	if rawU.RevisionID == "" {
		return nil, errors.Errorf("revision ID not found in %s", path)
	}

	if rawU.UpdateID == "" {
		return nil, errors.Errorf("update ID not found in %s", path)
	}

	creationDate, err := time.Parse(time.RFC3339, rawU.CreationDate)
	if err != nil {
		return nil, errors.Wrapf(err, "parse creation date %s", rawU.CreationDate)
	}

	u := microsoftkbUpdateTypes.Update{
		UpdateID:     rawU.UpdateID,
		CreationDate: creationDate,
		CatalogURL:   fmt.Sprintf("https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=%s", rawU.UpdateID),
	}

	var rawX wsusscn2.X
	if err := e.r.Read(filepath.Join(e.baseDir, "x", fmt.Sprintf("%s.json", rawU.RevisionID)), e.baseDir, &rawX); err != nil {
		return nil, errors.Wrapf(err, "read %s", filepath.Join(e.baseDir, "x", fmt.Sprintf("%s.json", rawU.RevisionID)))
	}

	if rawX.KBArticleID.Text == "" {
		return nil, nil
	}

	kbid := rawX.KBArticleID.Text
	u.SecurityBulletin = rawX.SecurityBulletinID.Text
	u.MSRCSeverity = rawX.MsrcSeverity
	u.SupportURL = rawX.SupportUrl.Text

	var rawL wsusscn2.L
	if err := e.r.Read(filepath.Join(e.baseDir, "l", fmt.Sprintf("%s.json", rawU.RevisionID)), e.baseDir, &rawL); err != nil {
		return nil, errors.Wrapf(err, "read %s", filepath.Join(e.baseDir, "l", fmt.Sprintf("%s.json", rawU.RevisionID)))
	}

	u.Title = rawL.Title.Text
	u.Description = rawL.Description.Text

	for _, rev := range rawU.SupersededBy.Revision {
		updateID, ok := revIDToUpdateID[rev.ID]
		if !ok {
			continue
		}

		su := microsoftkbSupersededByTypes.SupersededBy{UpdateID: updateID}

		var rawSX wsusscn2.X
		if err := e.r.Read(filepath.Join(e.baseDir, "x", fmt.Sprintf("%s.json", rev.ID)), e.baseDir, &rawSX); err != nil {
			return nil, errors.Wrapf(err, "read %s", filepath.Join(e.baseDir, "x", fmt.Sprintf("%s.json", rev.ID)))
		}

		if rawSX.KBArticleID.Text != "" {
			su.KBID = rawSX.KBArticleID.Text
		}

		u.SupersededBy = append(u.SupersededBy, su)
	}

	for _, c := range rawU.Categories.Category {
		switch c.Type {
		case "UpdateClassification":
			switch strings.ToUpper(c.ID) {
			case "5C9376AB-8CE6-464A-B136-22113DD69801":
				u.Classification = "Application"
			case "434DE588-ED14-48F5-8EED-A15E09A991F6":
				u.Classification = "Connectors"
			case "E6CF1350-C01B-414D-A61F-263D14D133B4":
				u.Classification = "CriticalUpdates"
			case "E0789628-CE08-4437-BE74-2495B842F43B":
				u.Classification = "DefinitionUpdates"
			case "E140075D-8433-45C3-AD87-E72345B36078":
				u.Classification = "DeveloperKits"
			case "B54E7D24-7ADD-428F-8B75-90A396FA584F":
				u.Classification = "FeaturePacks"
			case "9511D615-35B2-47BB-927F-F73D8E9260BB":
				u.Classification = "Guidance"
			case "0FA1201D-4330-4FA8-8AE9-B877473B6441":
				u.Classification = "SecurityUpdates"
			case "68C5B0A3-D1A6-4553-AE49-01D3A7827828":
				u.Classification = "ServicePacks"
			case "B4832BD8-E735-4761-8DAF-37F882276DAB":
				u.Classification = "Tools"
			case "28BC880E-0592-4CBF-8F95-C79B17911D5F":
				u.Classification = "UpdateRollups"
			case "CD5FFD1E-E932-4E3A-BF74-18BF0B1BBD83":
				u.Classification = "Updates"
			default:
				return nil, errors.Errorf("unknown Classification GUID: %s", c.ID)
			}
		case "ProductFamily":
			u.ProductFamily = strings.ToUpper(c.ID)
		case "Product":
			u.Products = append(u.Products, strings.ToUpper(c.ID))
		}
	}

	for _, l := range rawU.Languages.Language {
		u.Languages = append(u.Languages, l.Name)
	}

	return &microsoftkbTypes.KB{
		KBID:    kbid,
		URL:     fmt.Sprintf("https://support.microsoft.com/help/%s", kbid),
		Updates: []microsoftkbUpdateTypes.Update{u},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.MicrosoftWSUSSCN2,
			Raws: e.r.Paths(),
		},
	}, nil
}
