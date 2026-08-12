package util_test

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/update"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

func TestUnique(t *testing.T) {
	type test[T comparable] struct {
		name string
		args []T
		want []T
	}
	tests := []test[int]{
		{
			name: "int",
			args: []int{1, 1, 2},
			want: []int{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, util.Unique(tt.args), cmpopts.SortSlices(func(i, j int) bool { return i < j })); diff != "" {
				t.Errorf("Unique(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestRemoveAll(t *testing.T) {
	type args struct {
		root string
		opts []util.RemoveOption
	}
	tests := []struct {
		name string
		args args
		// entries are created directly under root before the call; each is a
		// directory when it ends in "/" and a file otherwise.
		entries []string
		want    []string
		wantErr bool
	}{
		{
			// README.md is no longer spared. The two extractors that publish
			// one write it immediately after this call, so keeping it only ever
			// preserved a copy about to be overwritten.
			name: "happy",
			args: args{
				root: "happy",
			},
			entries: []string{".git/", "README.md", "test.json"},
			want:    []string{".git"},
		},
		{
			// The option states the whole set, so .git has to be named to
			// survive alongside what the call adds.
			name: "keep",
			args: args{
				root: "keep",
				opts: []util.RemoveOption{util.WithKeep(".git", "README.md")},
			},
			entries: []string{".git/", "README.md", "data/", "test.json"},
			want:    []string{".git", "README.md"},
		},
		{
			// Which is also what makes .git droppable, the one way to empty a
			// tree completely.
			name: "keep nothing",
			args: args{
				root: "nothing",
				opts: []util.RemoveOption{util.WithKeep()},
			},
			entries: []string{".git/", "README.md", "data/", "test.json"},
			want:    []string{},
		},
		{
			// Repeating the option replaces rather than accumulates.
			name: "last option wins",
			args: args{
				root: "last",
				opts: []util.RemoveOption{util.WithKeep(".git"), util.WithKeep("README.md")},
			},
			entries: []string{".git/", "README.md", "test.json"},
			want:    []string{"README.md"},
		},
		{
			// A kept name is the entry's own name, not a suffix of it: keeping
			// "README.md" must not spare "OLD-README.md", nor ".git" spare
			// "bare.git".
			name: "keeps are not suffix matches",
			args: args{
				root: "exact",
				opts: []util.RemoveOption{util.WithKeep(".git", "README.md")},
			},
			entries: []string{".git/", "bare.git/", "README.md", "OLD-README.md"},
			want:    []string{".git", "README.md"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := filepath.Join(t.TempDir(), tt.args.root)
			if err := os.MkdirAll(d, 0750); err != nil {
				t.Fatal("unexpected error:", err)
			}

			for _, e := range tt.entries {
				if name, ok := strings.CutSuffix(e, "/"); ok {
					if err := os.Mkdir(filepath.Join(d, name), 0750); err != nil {
						t.Fatal("unexpected error:", err)
					}
					continue
				}
				f, err := os.Create(filepath.Join(d, e))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				f.Close()
			}

			if err := util.RemoveAll(d, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			es, err := os.ReadDir(d)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			got := make([]string, 0, len(es))
			for _, e := range es {
				got = append(got, e.Name())
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(x, y string) bool { return x < y })); diff != "" {
				t.Errorf("RemoveAll(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestSplit(t *testing.T) {
	type args struct {
		str        string
		delimiters []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "",
			args: args{
				str:        "a-b-c",
				delimiters: []string{"-"},
			},
			want: []string{"a", "b-c"},
		},
		{
			name: "",
			args: args{
				str:        "a-b:c",
				delimiters: []string{"-", ":"},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "",
			args: args{
				str:        "a-b:c",
				delimiters: []string{":", "-"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.Split(tt.args.str, tt.args.delimiters...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Split() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(i, j int) bool { return i < j })); diff != "" {
				t.Errorf("Split(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	tests := []struct {
		name     string
		content  any
		doSort   bool
		want     any
		hasError bool
	}{
		{
			name: "microsoftkb.KB",
			content: microsoftkbTypes.KB{
				KBID: "5070881",
				Updates: []microsoftkbUpdateTypes.Update{
					{UpdateID: "bbb"},
					{UpdateID: "aaa"},
				},
				DataSource: sourceTypes.Source{
					ID:   "microsoft-wsusscn2",
					Raws: []string{"c.json", "a.json", "b.json"},
				},
			},
			doSort: true,
			want: microsoftkbTypes.KB{
				KBID: "5070881",
				Updates: []microsoftkbUpdateTypes.Update{
					{UpdateID: "aaa"},
					{UpdateID: "bbb"},
				},
				DataSource: sourceTypes.Source{
					ID:   "microsoft-wsusscn2",
					Raws: []string{"a.json", "b.json", "c.json"},
				},
			},
		},
		{
			name: "pointer type with doSort errors",
			content: &microsoftkbTypes.KB{
				KBID: "5070881",
				Updates: []microsoftkbUpdateTypes.Update{
					{UpdateID: "bbb"},
					{UpdateID: "aaa"},
				},
				DataSource: sourceTypes.Source{
					ID:   "microsoft-wsusscn2",
					Raws: []string{"c.json", "a.json", "b.json"},
				},
			},
			doSort:   true,
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out.json")
			err := util.Write(path, tt.content, tt.doSort)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred; it must not have left an artifact behind
				if _, statErr := os.Stat(path); statErr == nil {
					t.Errorf("Write() returned an error but left a file at %s", path)
				}
				return
			default:
				f, err := os.Open(path)
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				defer f.Close()

				got := reflect.New(reflect.TypeOf(tt.want)).Interface()
				if err := json.UnmarshalRead(f, got); err != nil {
					t.Fatal("unexpected error:", err)
				}

				if diff := cmp.Diff(tt.want, reflect.ValueOf(got).Elem().Interface()); diff != "" {
					t.Errorf("Write(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
