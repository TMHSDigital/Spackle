package gitx

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// tarEntry is one entry of a crafted archive.
type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	body     string
	linkname string
}

// tarStream builds a tar archive in memory. The writer does no validation of
// names, so entries that point outside the destination are written as given.
func tarStream(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Linkname: e.linkname}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// exportDest returns an empty destination directory and its parent. The
// parent holds nothing else, so anything an archive writes next to the
// destination shows up in a listing of the parent.
func exportDest(t *testing.T) (parent, dest string) {
	t.Helper()
	parent = t.TempDir()
	dest = filepath.Join(parent, "dest")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	return parent, dest
}

// tree lists every entry below dir with forward slashes, sorted. Directories
// end with a slash. It uses Lstat semantics, so a symlink would be listed as
// an entry and not followed.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			rel += "/"
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func assertTree(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := tree(t, dir)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries below %s:\ngot  %q\nwant %q", dir, got, want)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func TestUntarSkipsEntriesThatLeaveTheDestination(t *testing.T) {
	parent, dest := exportDest(t)
	stream := tarStream(t,
		tarEntry{name: "../evil.txt", typeflag: tar.TypeReg, mode: 0o644, body: "evil"},
		tarEntry{name: "a/../../evil2.txt", typeflag: tar.TypeReg, mode: 0o644, body: "evil"},
		tarEntry{name: "../../evil3.txt", typeflag: tar.TypeReg, mode: 0o644, body: "evil"},
		tarEntry{name: "../evildir/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "..", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "ok.txt", typeflag: tar.TypeReg, mode: 0o644, body: "ok"},
	)
	if err := untar(bytes.NewReader(stream), dest); err != nil {
		t.Fatal(err)
	}
	// Only the harmless entry is written, and the entries after a skipped
	// one are still read.
	assertTree(t, dest, "ok.txt")
	assertFile(t, filepath.Join(dest, "ok.txt"), "ok")
	assertTree(t, parent, "dest/", "dest/ok.txt")
	if _, err := os.Lstat(filepath.Join(filepath.Dir(parent), "evil3.txt")); err == nil {
		t.Fatal("an entry two levels up was written above the destination")
	}
}

// A name that only starts with two dots is an ordinary name, not a way out.
func TestUntarKeepsNamesThatOnlyLookLikeTraversal(t *testing.T) {
	parent, dest := exportDest(t)
	stream := tarStream(t,
		tarEntry{name: "..hidden", typeflag: tar.TypeReg, mode: 0o644, body: "h"},
		tarEntry{name: "..dir/f.txt", typeflag: tar.TypeReg, mode: 0o644, body: "f"},
		tarEntry{name: "a/../b.txt", typeflag: tar.TypeReg, mode: 0o644, body: "b"},
	)
	if err := untar(bytes.NewReader(stream), dest); err != nil {
		t.Fatal(err)
	}
	assertTree(t, dest, "..hidden", "..dir/", "..dir/f.txt", "b.txt")
	assertTree(t, parent, "dest/", "dest/..hidden", "dest/..dir/", "dest/..dir/f.txt", "dest/b.txt")
}

func TestUntarConfinesAnAbsoluteNameToTheDestination(t *testing.T) {
	parent, dest := exportDest(t)
	// The name is unique to this run, so its absence at the root of the
	// file system can be asserted without guessing what else lives there.
	name := fmt.Sprintf("spackle-untar-test-%d-abs.txt", os.Getpid())
	stream := tarStream(t,
		tarEntry{name: "/" + name, typeflag: tar.TypeReg, mode: 0o644, body: "abs"},
		tarEntry{name: "/absdir/inner.txt", typeflag: tar.TypeReg, mode: 0o644, body: "inner"},
	)
	if err := untar(bytes.NewReader(stream), dest); err != nil {
		t.Fatal(err)
	}
	assertTree(t, dest, name, "absdir/", "absdir/inner.txt")
	assertFile(t, filepath.Join(dest, name), "abs")
	assertTree(t, parent, "dest/", "dest/"+name, "dest/absdir/", "dest/absdir/inner.txt")
	fsRoot := filepath.VolumeName(dest) + string(filepath.Separator)
	if _, err := os.Lstat(filepath.Join(fsRoot, name)); err == nil {
		_ = os.Remove(filepath.Join(fsRoot, name))
		t.Fatalf("an absolute entry name was written at %s", fsRoot)
	}
}

func TestUntarCreatesNothingForLinksAndSpecialFiles(t *testing.T) {
	parent, dest := exportDest(t)
	outside := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream := tarStream(t,
		tarEntry{name: "real.txt", typeflag: tar.TypeReg, mode: 0o644, body: "real"},
		tarEntry{name: "passwd", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/etc/passwd"},
		tarEntry{name: "up", typeflag: tar.TypeSymlink, mode: 0o777, linkname: ".."},
		tarEntry{name: "out", typeflag: tar.TypeSymlink, mode: 0o777, linkname: outside},
		tarEntry{name: "sub/link", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../real.txt"},
		tarEntry{name: "hard", typeflag: tar.TypeLink, mode: 0o644, linkname: "real.txt"},
		tarEntry{name: "hardout", typeflag: tar.TypeLink, mode: 0o644, linkname: "../outside.txt"},
		tarEntry{name: "fifo", typeflag: tar.TypeFifo, mode: 0o644},
		tarEntry{name: "chardev", typeflag: tar.TypeChar, mode: 0o644},
		// A file "inside" a skipped symlink must land in a real directory
		// below the destination, never in the directory the link named.
		tarEntry{name: "up/through.txt", typeflag: tar.TypeReg, mode: 0o644, body: "through"},
	)
	if err := untar(bytes.NewReader(stream), dest); err != nil {
		t.Fatal(err)
	}
	assertTree(t, dest, "real.txt", "up/", "up/through.txt")
	for _, rel := range []string{"real.txt", "up", "up/through.txt"} {
		st, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s is a symlink", rel)
		}
	}
	assertTree(t, parent, "dest/", "dest/real.txt", "dest/up/", "dest/up/through.txt", "outside.txt")
	assertFile(t, outside, "outside")
}

func TestUntarCreatesDirectories(t *testing.T) {
	_, dest := exportDest(t)
	stream := tarStream(t,
		tarEntry{name: "empty/", typeflag: tar.TypeDir, mode: 0o700},
		tarEntry{name: "d/e/f/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "d/e/file.txt", typeflag: tar.TypeReg, mode: 0o644, body: "x"},
		// A directory entry seen twice, and one that arrives after a file
		// already created it, are not errors.
		tarEntry{name: "d/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "empty/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "implied/by/file.txt", typeflag: tar.TypeReg, mode: 0o644, body: "y"},
	)
	if err := untar(bytes.NewReader(stream), dest); err != nil {
		t.Fatal(err)
	}
	assertTree(t, dest,
		"empty/", "d/", "d/e/", "d/e/f/", "d/e/file.txt",
		"implied/", "implied/by/", "implied/by/file.txt")
	for _, rel := range []string{"empty", "d", "d/e", "d/e/f", "implied", "implied/by"} {
		st, err := os.Stat(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if !st.IsDir() {
			t.Errorf("%s is not a directory", rel)
		}
		if runtime.GOOS == "windows" {
			continue // permission bits are not meaningful on Windows
		}
		if got := st.Mode().Perm(); got != 0o755 {
			t.Errorf("directory %s has mode %o, want 755", rel, got)
		}
	}
}

func TestUntarMapsTheExecutableBit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	_, dest := exportDest(t)
	cases := []struct {
		name string
		mode int64
		want os.FileMode
	}{
		{"exec.sh", 0o755, 0o755},
		{"plain.txt", 0o644, 0o644},
		{"owner-exec.sh", 0o700, 0o755},
		{"other-exec.sh", 0o601, 0o755},
		{"private.txt", 0o600, 0o644},
		{"none.txt", 0, 0o644},
		{"setuid", 0o4755, 0o755},
		{"world-writable.txt", 0o666, 0o644},
		{"nested/dir/run", 0o755, 0o755},
	}
	entries := make([]tarEntry, 0, len(cases))
	for _, c := range cases {
		entries = append(entries, tarEntry{name: c.name, typeflag: tar.TypeReg, mode: c.mode, body: "#!/bin/sh\n"})
	}
	if err := untar(bytes.NewReader(tarStream(t, entries...)), dest); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		st, err := os.Stat(filepath.Join(dest, filepath.FromSlash(c.name)))
		if err != nil {
			t.Fatal(err)
		}
		// The whole mode is compared, so a setuid or sticky bit that
		// survived would fail here too.
		if got := st.Mode() &^ os.ModeType; got != c.want {
			t.Errorf("%s (archive mode %o) has mode %v, want %v", c.name, c.mode, got, c.want)
		}
	}
}

func TestUntarOverwritesAnExistingFile(t *testing.T) {
	_, dest := exportDest(t)
	writeFile(t, dest, "a.txt", "a much longer old content\n")
	stream := tarStream(t,
		tarEntry{name: "a.txt", typeflag: tar.TypeReg, mode: 0o644, body: "new"},
		tarEntry{name: "twice.txt", typeflag: tar.TypeReg, mode: 0o644, body: "first, and longer"},
		tarEntry{name: "twice.txt", typeflag: tar.TypeReg, mode: 0o644, body: "second"},
	)
	if err := untar(bytes.NewReader(stream), dest); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dest, "a.txt"), "new")
	assertFile(t, filepath.Join(dest, "twice.txt"), "second")
}

func TestUntarEmptyStream(t *testing.T) {
	_, dest := exportDest(t)
	// git writes nothing to stdout when it rejects the revision.
	if err := untar(bytes.NewReader(nil), dest); err != nil {
		t.Fatalf("an empty stream: %v", err)
	}
	if err := untar(bytes.NewReader(tarStream(t)), dest); err != nil {
		t.Fatalf("an archive with no entries: %v", err)
	}
	assertTree(t, dest)
}

func TestUntarReturnsAnErrorForADamagedStream(t *testing.T) {
	body := strings.Repeat("0123456789abcdef", 256) // 4096 bytes, eight blocks
	full := tarStream(t,
		tarEntry{name: "first.txt", typeflag: tar.TypeReg, mode: 0o644, body: "first"},
		tarEntry{name: "big.txt", typeflag: tar.TypeReg, mode: 0o644, body: body},
	)
	garbage := bytes.Repeat([]byte("this is not a tar archive. "), 40)
	cases := []struct {
		name   string
		stream []byte
	}{
		// first.txt takes two blocks (header and one data block), then the
		// header of big.txt, then its data.
		{"cut inside a file body", full[:3*512+1000]},
		{"cut inside a header", full[:2*512+100]},
		{"cut inside the first header", full[:100]},
		{"not a tar archive", garbage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, dest := exportDest(t)
			if err := untar(bytes.NewReader(c.stream), dest); err == nil {
				t.Fatalf("untar returned no error; wrote %q", tree(t, dest))
			}
		})
	}
}

// zeros is a reader of n zero bytes.
type zeros struct{ n int64 }

func (z *zeros) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	clear(p)
	z.n -= int64(len(p))
	return len(p), nil
}

// The cap is the constant 64 MiB in untar and cannot be lowered from a test,
// so this writes a real file of that size. The archive is streamed through a
// pipe and never held in memory.
func TestUntarCutsAnOversizedFileAtTheCap(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 64 MiB file")
	}
	const fileCap = 64 << 20
	const extra = 3*512 + 7
	_, dest := exportDest(t)

	pr, pw := io.Pipe()
	werr := make(chan error, 1)
	go func() {
		tw := tar.NewWriter(pw)
		err := func() error {
			if err := tw.WriteHeader(&tar.Header{Name: "huge.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: fileCap + extra}); err != nil {
				return err
			}
			if _, err := io.Copy(tw, &zeros{n: fileCap + extra}); err != nil {
				return err
			}
			if err := tw.WriteHeader(&tar.Header{Name: "after.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5}); err != nil {
				return err
			}
			if _, err := tw.Write([]byte("after")); err != nil {
				return err
			}
			return tw.Close()
		}()
		_ = pw.CloseWithError(err)
		werr <- err
	}()

	uerr := untar(pr, dest)
	// Unblock the writer if untar stopped reading early.
	_ = pr.Close()
	if uerr != nil {
		t.Fatalf("untar: %v", uerr)
	}
	if err := <-werr; err != nil {
		t.Fatalf("writing the archive: %v", err)
	}
	st, err := os.Stat(filepath.Join(dest, "huge.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != fileCap {
		t.Fatalf("huge.bin is %d bytes, want it cut at the cap of %d", st.Size(), fileCap)
	}
	// The bytes past the cap are skipped, not mistaken for the next header.
	assertFile(t, filepath.Join(dest, "after.txt"), "after")
	assertTree(t, dest, "after.txt", "huge.bin")
}

// stageBlob writes content into the object database of dir and stages it at
// path with the given git mode, without needing the file system to support
// that mode. It is how a symlink is committed on Windows.
func stageBlob(t *testing.T, dir, mode, path, content string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sha := git(t, dir, "hash-object", "-w", "--", src)
	git(t, dir, "update-index", "--add", "--cacheinfo", mode+","+sha+","+path)
}

func TestArchiveSkipsCommittedSymlinks(t *testing.T) {
	dir := newRepo(t)
	ctx := context.Background()
	stageBlob(t, dir, "120000", "passwd", "/etc/passwd")
	stageBlob(t, dir, "120000", "up", "..")
	stageBlob(t, dir, "120000", "pkg/self", "../a.txt")
	stageBlob(t, dir, "100644", "pkg/sub/b.txt", "b\n")
	stageBlob(t, dir, "100755", "run.sh", "#!/bin/sh\n")
	// The index is committed as staged: "add -A" would drop the entries that
	// have no file in the work tree.
	git(t, dir, "commit", "-q", "-m", "links")
	head := git(t, dir, "rev-parse", "HEAD")
	if tracked := git(t, dir, "ls-tree", "-r", head); !strings.Contains(tracked, "120000 blob") {
		t.Fatalf("the commit holds no symlink, the test proves nothing:\n%s", tracked)
	}

	parent, dest := exportDest(t)
	if err := Archive(ctx, dir, head, dest); err != nil {
		t.Fatal(err)
	}
	assertTree(t, dest, "a.txt", "pkg/", "pkg/sub/", "pkg/sub/b.txt", "run.sh")
	assertTree(t, parent, "dest/", "dest/a.txt", "dest/pkg/", "dest/pkg/sub/", "dest/pkg/sub/b.txt", "dest/run.sh")
	assertFile(t, filepath.Join(dest, "pkg", "sub", "b.txt"), "b\n")
	if runtime.GOOS == "windows" {
		return // permission bits are not meaningful on Windows
	}
	for rel, want := range map[string]os.FileMode{"run.sh": 0o755, "a.txt": 0o644, "pkg/sub/b.txt": 0o644, "pkg": 0o755} {
		st, err := os.Stat(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s has mode %o, want %o", rel, got, want)
		}
	}
}

func TestArchiveRefusesARevisionThatIsAnOption(t *testing.T) {
	dir := newRepo(t)
	_, dest := exportDest(t)
	err := Archive(context.Background(), dir, "--output=x", dest)
	if err == nil || !strings.Contains(err.Error(), "is not valid") {
		t.Fatalf("err = %v, want the revision refused", err)
	}
	// git would have written the archive to a file named x in the repository.
	if _, serr := os.Lstat(filepath.Join(dir, "x")); serr == nil {
		t.Fatal("git archive ran and wrote the file named by the option")
	}
	assertTree(t, dest)
}

func TestArchiveUnknownRevisionReportsGitsFirstLine(t *testing.T) {
	dir := newRepo(t)
	_, dest := exportDest(t)
	const rev = "no-such-revision"
	err := Archive(context.Background(), dir, rev, dest)
	if err == nil {
		t.Fatal("Archive accepted a revision that does not exist")
	}
	msg, ok := strings.CutPrefix(err.Error(), "export "+rev+": ")
	if !ok {
		t.Fatalf("err = %q, want it to start with %q", err, "export "+rev+": ")
	}
	// The wording is git's own, so only its shape is checked: one line that
	// is not empty.
	if strings.TrimSpace(msg) == "" || strings.ContainsAny(msg, "\r\n") {
		t.Fatalf("err = %q, want one line of git's message after the prefix", err)
	}
	assertTree(t, dest)
}
