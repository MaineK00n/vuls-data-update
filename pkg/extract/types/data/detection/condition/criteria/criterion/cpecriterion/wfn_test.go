package cpecriterion

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
)

// equalValue reports whether two values are the same, byte for byte.
func equalValue(a, b wfnValue) bool {
	return a.any == b.any && a.na == b.na && bytes.Equal(a.unescaped, b.unescaped) &&
		a.p.lead == b.p.lead && a.p.trail == b.p.trail && bytes.Equal(a.p.core, b.p.core)
}

var wfnAttributes = [attrCount]string{
	common.AttributePart, common.AttributeVendor, common.AttributeProduct, common.AttributeVersion,
	common.AttributeUpdate, common.AttributeEdition, common.AttributeLanguage, common.AttributeSwEdition,
	common.AttributeTargetSw, common.AttributeTargetHw, common.AttributeOther,
}

// diffUnbindFS reports how unbindFS departs from go-cpe's naming.UnbindFS on
// fs: acceptance must agree, and each accepted attribute must carry the
// logical value, unescaped form and pattern go-cpe's value implies. A panic
// in go-cpe (a value ending in a lone backslash) counts as a rejection.
func diffUnbindFS(fs string) error {
	want, wantErr := func() (w common.WellFormedName, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return naming.UnbindFS(fs)
	}()
	got, gotErr := unbindFS(fs)
	switch {
	case wantErr != nil && gotErr != nil:
		return nil
	case wantErr != nil:
		return fmt.Errorf("go-cpe rejects, unbindFS accepts. fs: %q, go-cpe: %v", fs, wantErr)
	case gotErr != nil:
		return fmt.Errorf("go-cpe accepts, unbindFS rejects. fs: %q, unbindFS: %v", fs, gotErr)
	}
	for i, attr := range wfnAttributes {
		var w wfnValue
		switch v := want.Get(attr).(type) {
		case common.LogicalValue:
			w = naValue
			if v.IsANY() {
				w = anyValue
			}
		case string:
			w = wfnValue{unescaped: []byte(unescapeWFN(v)), p: parsePattern([]byte(v))}
		default:
			return fmt.Errorf("unexpected go-cpe value type. fs: %q, attribute: %s, value: %#v", fs, attr, v)
		}
		if !equalValue(got[i], w) {
			return fmt.Errorf("attribute differs. fs: %q, attribute: %s, go-cpe: %+v, unbindFS: %+v", fs, attr, w, got[i])
		}
	}
	return nil
}

var unbindFSSeeds = []string{
	"cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*",
	"CPE:2.3:O:Linux:Linux_Kernel:6.1.0:RC1:*:*:*:*:*:*",
	`cpe:2.3:o:cisco:ios:12.6(1)_es6:*:*:*:*:*:*:*`,
	`cpe:2.3:a:1c:1c\:enterprise:8.2\:1:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:1.0\\:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:*12:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:??12??:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:1?2:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:1*2:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:**:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:a\**:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:\-:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:-:-:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:?:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:x\`,
	`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:`,
	`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product::*:*:*:*:*:*:*`,
	`cpe:2.3:*:vendor:product:1.0:*:*:*:*:*:*:*`,
	`cpe:2.3:\a:vendor:product:1.0:*:*:*:*:*:*:*`,
	`cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:1 0:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:バージョン:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:1.0\` + "\x00" + `:*:*:*:*:*:*:*`,
	`cpe:2.3:a:vendor:product:\\\:x:*:*:*:*:*:*:*`,
	`cpe:2.4:a:vendor:product:1.0:*:*:*:*:*:*:*`,
	`cpe:/a:vendor:product:1.0`,
	"",
}

func TestUnbindFS(t *testing.T) {
	for _, fs := range unbindFSSeeds {
		if err := diffUnbindFS(fs); err != nil {
			t.Error(err)
		}
	}
}

func FuzzUnbindFS(f *testing.F) {
	for _, fs := range unbindFSSeeds {
		f.Add(fs)
	}
	f.Fuzz(func(t *testing.T, fs string) {
		if err := diffUnbindFS(fs); err != nil {
			t.Error(err)
		}
	})
}

// diffUnbindReduced reports how unbindReduced departs from unbinding the
// full name Unpack restores for the reduced entry e: acceptance must agree,
// and so must every attribute, whether the WFN is fresh or left by a
// previous entry that set every attribute.
func diffUnbindReduced(e string) error {
	const prefix = "cpe:2.3:a:vendor:product:"
	c, err := unbindFS(prefix + "*:*:*:*:*:*:*:*")
	if err != nil {
		return err
	}
	want, wantErr := unbindFS(string(fullName(prefix, []byte(e))))
	for _, previous := range []string{"", "1:2:3:4:5:6:7:8"} {
		got := packedWFN(&c)
		if previous != "" {
			if err := unbindReduced(prefix, []byte(previous), &got); err != nil {
				return err
			}
		}
		gotErr := unbindReduced(prefix, []byte(e), &got)
		switch {
		case wantErr != nil && gotErr != nil:
			continue
		case wantErr != nil:
			return fmt.Errorf("unbindFS rejects, unbindReduced accepts. entry: %q, unbindFS: %v", e, wantErr)
		case gotErr != nil:
			return fmt.Errorf("unbindFS accepts, unbindReduced rejects. entry: %q, unbindReduced: %v", e, gotErr)
		}
		for i, attr := range wfnAttributes {
			if !equalValue(got[i], want[i]) {
				return fmt.Errorf("attribute differs. entry: %q, after: %q, attribute: %s, unbindFS: %+v, unbindReduced: %+v", e, previous, attr, want[i], got[i])
			}
		}
	}
	return nil
}

var unbindReducedSeeds = []string{
	"",
	"12.0",
	"12.0:beta1",
	"12.0:beta1:*:*:*:*:*:*",
	"12.0:*:x",
	"12.0.6099.109",
	"6.1.0:rc1",
	"12.6(1)_es6",
	"RC1:Beta",
	`8.2\:1`,
	`8.2:build\:7`,
	`1.0\\`,
	`1.0\\:x`,
	`1.0\`,
	`1.0\:x\\`,
	"12.0::x",
	":12.0",
	"12.0:",
	"1:2:3:4:5:6:7:8:9",
	"1:2:3:4:5:6:7:8",
	"1:2:3:4:5:6:7:",
	"1:2:3:4:5:6::",
	"1:2:3:4:5:6:7::",
	"1:2:3:4:5:6:7::9",
	"-",
	"*",
	"1.*",
	"*1",
	"1*2",
	"??1",
	"1?2",
	"**",
	"1 0",
	"バージョン",
	"1.0\x00",
	`\-`,
	`1\.0`,
}

func TestUnbindReduced(t *testing.T) {
	for _, e := range unbindReducedSeeds {
		if err := diffUnbindReduced(e); err != nil {
			t.Error(err)
		}
	}
}

func FuzzUnbindReduced(f *testing.F) {
	for _, e := range unbindReducedSeeds {
		f.Add(e)
	}
	f.Fuzz(func(t *testing.T, e string) {
		if err := diffUnbindReduced(e); err != nil {
			t.Error(err)
		}
	})
}
