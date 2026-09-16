package filepath

import (
	"path/filepath"

	"github.com/pkg/errors"
)

// Join returns filepath.Join(root, elems...) and an error when the result
// escapes root.
//
// Fetchers build their output paths out of identifiers that came from the
// document they just downloaded, and those reach filepath.Join as a single
// element: an ID such as "CVE-2024-../../../outside" cleans its way out of
// the tree and writes wherever it points. Nothing upstream of here checks
// that, so the last chance to catch it is where the path is assembled.
//
// The check is lexical: filepath.IsLocal resolves ".." but not symlinks, so a
// symlinked component already inside root still leads out of it. Planting
// one takes write access to the output tree, which is a different position
// to be in than serving a crafted document, and os.Root is what closes that
// gap — it would replace the path assembly here rather than extend it.
func Join(root string, elems ...string) (string, error) {
	name := filepath.Join(elems...)

	// filepath.IsLocal is the whole contract: name stays inside the directory
	// it is relative to. An empty name is not local by that definition but is
	// simply the root itself, which is a caller joining nothing.
	if name != "" && !filepath.IsLocal(name) {
		return "", errors.Errorf("unexpected path. expected: %s, actual: %q", "a path under "+root, filepath.Join(root, name))
	}

	return filepath.Join(root, name), nil
}
