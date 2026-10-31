package nvfs

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
)

// TestCanonDifferential pins C++ canonName parity with Go
// sqlite.CanonicalPath over tricky spellings. Both resolve relative
// paths against the same process cwd, so results must agree byte
// for byte.
func TestCanonDifferential(t *testing.T) {
	inputs := []string{
		"/db/murmur",
		"/db/murmur-journal",
		"/db/murmur-wal",
		"/",
		"",
		".",
		"..",
		"rel/path",
		"./rel/./path",
		"rel/../other",
		"../../up",
		"/a//b///c",
		"/a/./b",
		"/a/b/../c",
		"/a/b/../../..",
		"/..",
		"/../..",
		"/a/b/",
		"a/",
		"a//",
		"a/../../b",
		"a/b/../../../c",
		"/a/.../b",
		"/a/...b/c",
		"file:/db/murmur",
		"file:relative/path",
		"file:/db/murmur?vfs=native&cache=shared",
		"file:rel?query",
		"file://host/db/murmur",
		"file://host/",
		"file://host",
		"file://",
		"file:",
		"file:?query",
		"file:///abs/path",
		"file:/a%20b/c",
		"file:/a%2Fb",
		"file:/100%25",
		"file:/%41%42%43",
		"file:/%zz/stuff",
		"file:/%a",
		"file:/%",
		"file:/a%",
		"file:/a%2",
		"file:/a%2x",
		"/not-a-uri/%20",
		"/db/murmur-journal-journal",
		"/x-y",
		"file://h/a/b?x=%41",
	}
	check := func(in string) {
		t.Helper()
		got, ok := canonTestCPP(in)
		if !ok {
			t.Fatalf("canon(%q): C++ returned nil", in)
		}
		want := sqlite.CanonicalPath(in)
		if got != want {
			t.Errorf("canon(%q): C++ %q, Go %q", in, got, want)
		}
	}
	for _, in := range inputs {
		check(in)
	}
	// Randomized segment soup (deterministic): the ../.// pop logic
	// has bitten once; hammer it against the Go form.
	segs := []string{"a", "bb", ".", "..", "...", "", "x-y", ".h", "h."}
	rng := rand.New(rand.NewSource(0xCA407))
	for i := 0; i < 600; i++ {
		n := 1 + rng.Intn(6)
		p := ""
		if rng.Intn(2) == 0 {
			p = "/"
		} else if rng.Intn(3) == 0 {
			p = "file:" + p
		}
		for k := 0; k < n; k++ {
			p += segs[rng.Intn(len(segs))]
			if k+1 < n || rng.Intn(3) == 0 {
				p += "/"
			}
		}
		if strings.HasPrefix(p, "file:") && rng.Intn(2) == 0 {
			p += "?vfs=native"
		}
		check(p)
	}
}
