package util

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGitEnv(t *testing.T) {
	tests := []struct {
		name string
		// env is set while git runs on a repository. other is another
		// repository, which git must leave alone.
		env func(other string) map[string]string
		// wantConfig is test.key as git reads it in the repository.
		wantConfig string
	}{
		{
			name: "GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE of another repository",
			env: func(other string) map[string]string {
				return map[string]string{
					"GIT_DIR":        filepath.Join(other, ".git"),
					"GIT_WORK_TREE":  other,
					"GIT_INDEX_FILE": filepath.Join(other, ".git", "index"),
				}
			},
			wantConfig: "repository",
		},
		{
			name: "GIT_COMMON_DIR and GIT_OBJECT_DIRECTORY of another repository",
			env: func(other string) map[string]string {
				return map[string]string{
					"GIT_COMMON_DIR":       filepath.Join(other, ".git"),
					"GIT_OBJECT_DIRECTORY": filepath.Join(other, ".git", "objects"),
				}
			},
			wantConfig: "repository",
		},
		{
			name: "GIT_CONFIG at the config file of another repository",
			env: func(other string) map[string]string {
				return map[string]string{
					"GIT_CONFIG": filepath.Join(other, ".git", "config"),
				}
			},
			wantConfig: "repository",
		},
		{
			name: "config through GIT_CONFIG_COUNT",
			env: func(string) map[string]string {
				return map[string]string{
					"GIT_CONFIG_COUNT":   "1",
					"GIT_CONFIG_KEY_0":   "test.key",
					"GIT_CONFIG_VALUE_0": "count",
				}
			},
			wantConfig: "count",
		},
		{
			name: "config through GIT_CONFIG_PARAMETERS, with GIT_DIR of another repository",
			env: func(other string) map[string]string {
				return map[string]string{
					"GIT_DIR":               filepath.Join(other, ".git"),
					"GIT_CONFIG_PARAMETERS": "'test.key'='parameters'",
				}
			},
			wantConfig: "parameters",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Leave out the config of the user, and the config values this
			// process would pass on through the environment, so that nothing
			// they turn on, such as hooks or fsmonitor, writes to the
			// repositories, and only env overrides test.key.
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"} {
				unsetenv(t, key)
			}

			dir := t.TempDir()
			repository := filepath.Join(dir, "repository")
			other := filepath.Join(dir, "other")
			head := initRepository(t, repository)
			initRepository(t, other)
			before := snapshot(t, other)

			for k, v := range tt.env(other) {
				t.Setenv(k, v)
			}

			if got := run(t, "-C", repository, "rev-parse", "HEAD"); got != head {
				t.Errorf("HEAD. expected: %q, actual: %q", head, got)
			}
			if got := run(t, "-C", repository, "config", "--default", "", "--get", "test.key"); got != tt.wantConfig {
				t.Errorf("test.key. expected: %q, actual: %q", tt.wantConfig, got)
			}

			// Write the index, an object, a ref and the config.
			if err := os.WriteFile(filepath.Join(repository, "file"), []byte("file\n"), 0644); err != nil {
				t.Fatalf("write file. err: %v", err)
			}
			run(t, "-C", repository, "add", "file")
			run(t, "-C", repository, "update-ref", "refs/heads/written", "HEAD")
			run(t, "-C", repository, "config", "test.written", "true")

			if diff := cmp.Diff(before, snapshot(t, other)); diff != "" {
				t.Errorf("other repository changed. (-before +after):\n%s", diff)
			}
			if got := run(t, "-C", repository, "ls-files"); got != "file" {
				t.Errorf("index. expected: %q, actual: %q", "file", got)
			}
			if got := run(t, "-C", repository, "rev-parse", "refs/heads/written"); got != head {
				t.Errorf("refs/heads/written. expected: %q, actual: %q", head, got)
			}
			if got := run(t, "-C", repository, "config", "--local", "--get", "test.written"); got != "true" {
				t.Errorf("test.written. expected: %q, actual: %q", "true", got)
			}
		})
	}
}

// initRepository makes a repository at dir with a commit of its own, and
// test.key set to the name of dir, and returns the commit. Plumbing, unlike
// git commit, starts no background maintenance that could write to the
// repository while a test compares it.
func initRepository(t *testing.T, dir string) string {
	t.Helper()
	run(t, "init", "--quiet", dir)
	run(t, "-C", dir, "config", "test.key", filepath.Base(dir))
	tree := run(t, "-C", dir, "write-tree")
	commit := run(t, "-C", dir, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit-tree", "-m", filepath.Base(dir), tree)
	run(t, "-C", dir, "update-ref", "HEAD", commit)
	return commit
}

// snapshot reads every file under dir, by path relative to dir.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		bs, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files[rel] = string(bs)
		return nil
	}); err != nil {
		t.Fatalf("walk %s. err: %v", dir, err)
	}
	return files
}

// unsetenv unsets key until the test ends, when t.Setenv puts it back.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv %s. err: %v", key, err)
	}
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	bs, err := Git(args...)
	if err != nil {
		t.Fatalf("run git. err: %v", err)
	}
	return strings.TrimSpace(string(bs))
}
