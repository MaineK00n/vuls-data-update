package json

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	panosVersion "github.com/MaineK00n/go-paloalto-version/pan-os"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	paloaltoJSON "github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/json"
)

// TestValidateXAffectedList cross-validates the PAN-OS changes interpretation
// against the x_affectedList enumeration that most raw records carry: every
// criterion set produced from versions[] is evaluated over the universe of
// PAN-OS versions observed anywhere in the dataset, and the accepted set is
// compared with the record's own x_affectedList.
//
// Opt-in: set PALOALTO_JSON_RAW_DIR to a checkout of vuls-data-raw-paloalto-json.
func TestValidateXAffectedList(t *testing.T) {
	rawDir := os.Getenv("PALOALTO_JSON_RAW_DIR")
	if rawDir == "" {
		t.Skip("PALOALTO_JSON_RAW_DIR is not set")
	}

	type record struct {
		id       string
		fetched  paloaltoJSON.CVE
		expected map[string]struct{}
	}

	var records []record
	universe := map[string]panosVersion.Version{}
	if err := filepath.WalkDir(rawDir, func(path string, d fs.DirEntry, err error) error {
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

		var fetched paloaltoJSON.CVE
		if err := utiljson.NewJSONReader().Read(path, rawDir, &fetched); err != nil {
			return err
		}

		r := record{id: fetched.CVEMetadata.CVEID, fetched: fetched, expected: map[string]struct{}{}}
		ls, ok := fetched.Containers.CNA.XAffectedList.([]any)
		if !ok {
			return nil
		}
		for _, l := range ls {
			s, ok := l.(string)
			if !ok {
				continue
			}
			rest, ok := strings.CutPrefix(s, "PAN-OS ")
			if !ok {
				continue
			}
			v, err := parsePANOSVersion(rest)
			if err != nil {
				continue
			}
			universe[v.String()] = v
			r.expected[v.String()] = struct{}{}
		}
		if len(r.expected) > 0 {
			records = append(records, r)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %s", rawDir, err)
	}

	vs := slices.Collect(maps.Keys(universe))
	slices.SortFunc(vs, func(a, b string) int { return universe[a].Compare(universe[b]) })
	t.Logf("records: %d, version universe: %d", len(records), len(vs))

	var totalFN, totalFP, fnRecords, fpRecords int
	for _, r := range records {
		var rangeCriteria []ccTypes.Criterion
		for _, d := range detections(r.fetched) {
			for _, c := range d.Conditions {
				for _, cn := range c.Criteria.Criterions {
					if cn.CPE == nil || string(cn.CPE.CPE) != panosCPE || len(cn.CPE.CPEMatches) > 0 {
						continue
					}
					rangeCriteria = append(rangeCriteria, *cn.CPE)
				}
			}
		}

		var fns, fps []string
		for _, v := range vs {
			query := ccTypes.Query{CPE: fmt.Sprintf("cpe:2.3:o:paloaltonetworks:pan-os:%s:*:*:*:*:*:*:*", v)}
			accepted := false
			for _, cn := range rangeCriteria {
				ok, err := cn.Accept(query)
				if err != nil {
					t.Fatalf("%s: accept %s: %s", r.id, v, err)
				}
				if ok {
					accepted = true
					break
				}
			}
			_, expected := r.expected[v]
			switch {
			case expected && !accepted:
				fns = append(fns, v)
			case !expected && accepted:
				fps = append(fps, v)
			}
		}
		totalFN += len(fns)
		totalFP += len(fps)
		if len(fns) > 0 {
			fnRecords++
		}
		if len(fps) > 0 {
			fpRecords++
		}
		if len(fns) > 0 || len(fps) > 0 {
			t.Logf("%s: false negatives: %d %v, false positives: %d %v", r.id, len(fns), truncate(fns, 10), len(fps), truncate(fps, 10))
		}
	}
	t.Logf("total false negatives: %d (%d records), false positives: %d (%d records)", totalFN, fnRecords, totalFP, fpRecords)
}

func truncate(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return append(slices.Clone(ss[:n]), "...")
}
