package oval

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval" // SUSE OVAL用のfetchパッケージ
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

type extractor struct {
	inputDir string
	baseDir  string
	osname   string
	version  string
	ovaltype string
	r        *utiljson.JSONReader
}

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "oval"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract SUSE OVAL")

	entries, err := filepath.Glob(filepath.Join(inputDir, "*", "*", "*", "definitions"))
	if err != nil {
		return errors.Wrapf(err, "glob directories \"*/*/*/definitions\" under %s", inputDir)
	}

	for _, entry := range entries {
		elems, err := util.Split(strings.TrimPrefix(entry, inputDir), string(os.PathSeparator), string(os.PathSeparator), string(os.PathSeparator))
		if err != nil {
			return errors.Wrapf(err, "split %s", entry)
		}

		baseDir := filepath.Join(inputDir, elems[0], elems[1], elems[2])
		if err := filepath.WalkDir(filepath.Join(baseDir, "definitions"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			e := extractor{
				inputDir: inputDir,
				baseDir:  baseDir,
				r:        utiljson.NewJSONReader(),
			}
			var def oval.Definition
			if err := e.r.Read(path, e.baseDir, &def); err != nil {
				return errors.Wrapf(err, "read json %s", path)
			}

			_, err = e.extract(def)
			if err != nil {
				return errors.Wrapf(err, "extract %s", path)
			}

			// SUSE用のID形式に対応した分割処理
			// 例: SUSE-SU-2023-1234-1 のような形式を想定
			// splitted, err := util.Split(string(data.ID), "-", "-")
			// if err != nil {
			// 	return errors.Wrapf(err, "unexpected ID format for SUSE. actual: %q", data.ID)
			// }

			// if len(splitted) < 3 {
			// 	return errors.Errorf("unexpected SUSE ID format. expected: SUSE-<TYPE>-<YEAR>-<ID>, actual: %q", data.ID)
			// }

			// // SUSE-SU-2023-1234-1 -> year = 2023
			// year := splitted[2]
			// if _, err := time.Parse("2006", year); err != nil {
			// 	return errors.Wrapf(err, "unexpected year format in ID. actual: %q", data.ID)
			// }

			// if err := util.Write(filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			// 	return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", data.ID)))
			// }

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", inputDir)
		}

	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.SUSEOVAL,
		Name: func() *string { t := "SUSE OVAL"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(inputDir)
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

func (e extractor) extract(def oval.Definition) (dataTypes.Data, error) {
	id := ""
	switch def.Class {
	case "patch":
		for _, r := range def.Metadata.Reference {
			if r.Source == "SUSE-SU" {
				if id != "" {
					return dataTypes.Data{}, errors.Errorf("multiple SUSE-SU references found. definition: %s", def.ID)
				}
				id = r.RefID
			}
		}
	case "vulnerability":
		if !strings.HasPrefix(def.ID, "CVE-") {
			return dataTypes.Data{}, errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-YYYY-ZZZZZ", def.ID)
		}
		id = def.Metadata.Title
	default:
		return dataTypes.Data{}, errors.Errorf("unexpected class %s in definition %s (%s/%s)", def.Class, def.ID, e.osname, e.version)
	}

	// TODO: SUSE固有のデータ抽出ロジックを実装
	// - パッケージ情報の収集
	// - 脆弱性情報の抽出
	// - セキュリティアドバイザリ情報の構築

	// 基本的なデータ構造を返す（実装は要調整）
	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		// Advisories: // TODO: アドバイザリ情報を構築
		// Vulnerabilities: // TODO: 脆弱性情報を構築
		// Detections: // TODO: 検出条件を構築
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.SUSEOVAL,
			Raws: e.r.Paths(),
		},
	}, nil
}
