package diff_test

import (
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/diff"
)

func TestDiff(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}

	cmd := exec.Command("git", "daemon", "--listen=127.0.0.1", "--reuseaddr", "--export-all", "--base-path=./testdata/fixtures/")
	if err := cmd.Start(); err != nil {
		t.Fatalf("git daemon. error = %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	}()

	if err := waitForDaemonStarted(); err != nil {
		t.Fatalf("git daemon did not start. err = %v", err)
	}

	type args struct {
		datasource string
		rootID     string
		old        string
		new        string
		opts       []diff.Option
	}
	tests := []struct {
		name    string
		args    args
		want    diff.WholeDiff
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				datasource: "diff-test",
				rootID:     "TEST-001",
				old:        "04e7d58",
				new:        "940ba69",
				opts:       []diff.Option{diff.WithDir(t.TempDir()), diff.WithRemotePrefix("git://127.0.0.1")},
			},
			want: diff.WholeDiff{
				RootID: "TEST-001",
				Extracted: map[string]diff.Repository{
					"vuls-data-extracted-diff-test": {
						Commits: diff.CommitRange{
							Old: "04e7d58",
							New: "940ba69",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "data/TEST-001.json",
									New: "data/TEST-001.json",
								},
								Diff: "diff --git a/data/TEST-001.json b/data/TEST-001.json\nindex c1e037e..c9b4e19 100644\n--- a/data/TEST-001.json\n+++ b/data/TEST-001.json\n@@ -4,7 +4,7 @@\n \t\t{\n \t\t\t\"content\": {\n \t\t\t\t\"id\": \"CVE-2024-XXXX\",\n-\t\t\t\t\"description\": \"For diff test\"\n+\t\t\t\t\"description\": \"For diff test, modified\"\n \t\t\t}\n \t\t}\n \t],\n",
							},
						},
					},
				},
				Raw: map[string]diff.Repository{
					"vuls-data-raw-diff-test": {
						Commits: diff.CommitRange{
							Old: "6e91a08d809ca51df9078e960c7743bd919539c8",
							New: "bde914b7ed12c210437955cc4a49f94f29b0f96d",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "TEST-001.json",
									New: "TEST-001.json",
								},
								Diff: "diff --git a/TEST-001.json b/TEST-001.json\nindex 480117b..5b9a1fa 100644\n--- a/TEST-001.json\n+++ b/TEST-001.json\n@@ -1,4 +1,4 @@\n {\n   \"id\": 1,\n-  \"data\": \"abc\"\n+  \"added\": \"xyz\"\n }\n\\ No newline at end of file\n",
							},
						},
					},
				},
			},
		},
		{
			name: "without-raw-new",
			args: args{
				datasource: "diff-test",
				rootID:     "TEST-001",
				old:        "940ba69",
				new:        "2e09855",
				opts:       []diff.Option{diff.WithDir(t.TempDir()), diff.WithRemotePrefix("git://127.0.0.1")},
			},
			want: diff.WholeDiff{RootID: "TEST-001",
				Extracted: map[string]diff.Repository{
					"vuls-data-extracted-diff-test": {
						Commits: diff.CommitRange{
							Old: "940ba69",
							New: "2e09855",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "data/TEST-001.json",
									New: "data/TEST-001.json",
								},
								Diff: "diff --git a/data/TEST-001.json b/data/TEST-001.json\nindex c9b4e19..b9d63c7 100644\n--- a/data/TEST-001.json\n+++ b/data/TEST-001.json\n@@ -1,17 +1,8 @@\n {\n \t\"id\": \"TEST-001\",\n-\t\"vulnerabilities\": [\n-\t\t{\n-\t\t\t\"content\": {\n-\t\t\t\t\"id\": \"CVE-2024-XXXX\",\n-\t\t\t\t\"description\": \"For diff test, modified\"\n-\t\t\t}\n-\t\t}\n-\t],\n+\t\"vulnerabilities\": [],\n \t\"data_source\": {\n \t\t\"id\": \"test\",\n-\t\t\"raws\": [\n-\t\t\t\"vuls-data-raw-diff-test/TEST-001.json\"\n-\t\t]\n+\t\t\"raws\": []\n \t}\n }\n\\ No newline at end of file\n",
							},
						},
					},
				},
				Raw: map[string]diff.Repository{
					"vuls-data-raw-diff-test": {
						Commits: diff.CommitRange{
							Old: "bde914b7ed12c210437955cc4a49f94f29b0f96d",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "TEST-001.json",
								},
								Diff: "-{\n-  \"id\": 1,\n-  \"added\": \"xyz\"\n-}\n"},
						},
					},
				},
			},
		},

		{
			name: "without-raw-old",
			args: args{
				datasource: "diff-test",
				rootID:     "TEST-001",
				old:        "2e09855",
				new:        "59a0afe",
				opts:       []diff.Option{diff.WithDir(t.TempDir()), diff.WithRemotePrefix("git://127.0.0.1")},
			},
			want: diff.WholeDiff{
				RootID: "TEST-001",
				Extracted: map[string]diff.Repository{
					"vuls-data-extracted-diff-test": {
						Commits: diff.CommitRange{
							Old: "2e09855",
							New: "59a0afe",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "data/TEST-001.json",
									New: "data/TEST-001.json",
								},
								Diff: "diff --git a/data/TEST-001.json b/data/TEST-001.json\nindex b9d63c7..c1e037e 100644\n--- a/data/TEST-001.json\n+++ b/data/TEST-001.json\n@@ -1,8 +1,17 @@\n {\n \t\"id\": \"TEST-001\",\n-\t\"vulnerabilities\": [],\n+\t\"vulnerabilities\": [\n+\t\t{\n+\t\t\t\"content\": {\n+\t\t\t\t\"id\": \"CVE-2024-XXXX\",\n+\t\t\t\t\"description\": \"For diff test\"\n+\t\t\t}\n+\t\t}\n+\t],\n \t\"data_source\": {\n \t\t\"id\": \"test\",\n-\t\t\"raws\": []\n+\t\t\"raws\": [\n+\t\t\t\"vuls-data-raw-diff-test/TEST-001.json\"\n+\t\t]\n \t}\n }\n\\ No newline at end of file\n",
							},
						},
					},
				},
				Raw: map[string]diff.Repository{
					"vuls-data-raw-diff-test": {
						Commits: diff.CommitRange{
							New: "6e91a08d809ca51df9078e960c7743bd919539c8",
						},
						Files: []diff.FileDiff{{
							Path: diff.Path{
								New: "TEST-001.json",
							},
							Diff: "+{\n+  \"id\": 1,\n+  \"data\": \"abc\"\n+}\n"},
						},
					},
				},
			},
		},
		{
			name: "extracted-file-rename",
			args: args{
				datasource: "diff-test",
				rootID:     "TEST-001",
				old:        "59a0afe",
				new:        "4a2d523",
				opts:       []diff.Option{diff.WithDir(t.TempDir()), diff.WithRemotePrefix("git://127.0.0.1")},
			},
			want: diff.WholeDiff{
				RootID: "TEST-001",
				Extracted: map[string]diff.Repository{
					"vuls-data-extracted-diff-test": {
						Commits: diff.CommitRange{
							Old: "59a0afe",
							New: "4a2d523",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									New: "data/2024/TEST-001.json",
									Old: "data/TEST-001.json",
								},
								Diff: "diff --git a/data/TEST-001.json b/data/2024/TEST-001.json\nsimilarity index 100%\nrename from data/TEST-001.json\nrename to data/2024/TEST-001.json\n",
							},
						},
					},
				},
				Raw: map[string]diff.Repository{
					"vuls-data-raw-diff-test": {
						Commits: diff.CommitRange{
							Old: "6e91a08d809ca51df9078e960c7743bd919539c8",
							New: "6e91a08d809ca51df9078e960c7743bd919539c8",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "TEST-001.json",
									New: "TEST-001.json",
								},
								Diff: "",
							},
						},
					},
				},
			},
		},
		{
			name: "old-in-archive-1",
			args: args{
				datasource: "diff-test",
				rootID:     "TEST-001",
				old:        "4a2d523",
				new:        "2660207",
				opts:       []diff.Option{diff.WithDir(t.TempDir()), diff.WithRemotePrefix("git://127.0.0.1")},
			},
			want: diff.WholeDiff{
				RootID: "TEST-001",
				Extracted: map[string]diff.Repository{
					"vuls-data-extracted-diff-test": {
						Commits: diff.CommitRange{
							Old: "4a2d523",
							New: "2660207",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "data/2024/TEST-001.json",
									New: "data/TEST-001.json",
								},
								Diff: "diff --git a/data/2024/TEST-001.json b/data/TEST-001.json\nsimilarity index 100%\nrename from data/2024/TEST-001.json\nrename to data/TEST-001.json\n",
							},
						},
					},
				},
				Raw: map[string]diff.Repository{
					"vuls-data-raw-diff-test": {
						Commits: diff.CommitRange{
							Old: "6e91a08d809ca51df9078e960c7743bd919539c8",
							New: "6e91a08d809ca51df9078e960c7743bd919539c8",
						},
						Files: []diff.FileDiff{
							{
								Path: diff.Path{
									Old: "TEST-001.json",
									New: "TEST-001.json",
								},
								Diff: "",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := diff.Diff(tt.args.datasource, tt.args.rootID, tt.args.old, tt.args.new, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Diff() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Diff(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func waitForDaemonStarted() error {
	for i := 0; i < 30; i++ {
		cmd := exec.Command("git", "ls-remote", "--exit-code", "git://127.0.0.1/vuls-data-extracted-diff-test.git", "main")
		if err := cmd.Run(); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.Errorf("git daemon did not started")
}
