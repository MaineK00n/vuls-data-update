package concat

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGroupRefs(t *testing.T) {
	type args struct {
		before  []input
		shallow []string
	}
	tests := []struct {
		name     string
		g        group
		args     args
		want     map[string]string
		hasError bool
	}{
		{
			name: "a shallow root held by the group before",
			g: group{
				{path: "/a/archive-3", refs: map[string]string{"refs/heads/main": "c4"}},
				{path: "/a/archive-4", refs: map[string]string{"refs/heads/main": "c5", "refs/tags/v1": "c5"}},
			},
			args: args{
				before: []input{
					{path: "/a/archive-1", refs: map[string]string{"refs/heads/main": "c2", "refs/tags/v0": "c1"}},
					{path: "/a/archive-2", refs: map[string]string{"refs/heads/main": "c3", "refs/heads/nightly": "c3", "refs/heads/old": "c2"}},
				},
				shallow: []string{"c3"},
			},
			want: map[string]string{
				"refs/heads/main":             "c5",
				"refs/tags/v1":                "c5",
				"refs/tags/archive-2/main":    "c3",
				"refs/tags/archive-2/nightly": "c3",
				"refs/tags/archive-3/main":    "c4",
				"refs/tags/archive-4/main":    "c5",
			},
		},
		{
			name: "no shallow root",
			g: group{
				{path: "/a/archive-2", refs: map[string]string{"refs/heads/main": "c3"}},
			},
			args: args{
				before: []input{
					{path: "/a/archive-1", refs: map[string]string{"refs/heads/main": "c2"}},
				},
			},
			want: map[string]string{
				"refs/heads/main":          "c3",
				"refs/tags/archive-2/main": "c3",
			},
		},
		{
			name: "a tag of the group at another commit",
			g: group{
				{path: "/a/archive-2", refs: map[string]string{"refs/heads/main": "c3", "refs/tags/archive-1/main": "c1"}},
			},
			args: args{
				before: []input{
					{path: "/a/archive-1", refs: map[string]string{"refs/heads/main": "c2"}},
				},
				shallow: []string{"c2"},
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.g.refs(tt.args.before, tt.args.shallow)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("(-expected +got):\n%s", diff)
				}
			}
		})
	}
}
