package vfs

import (
	"bytes"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
)

const testManifest = `{
  "defaults": {"uname":"root","gname":"root","dirmode":"0755","filemode":"0644","mtime":"-30d"},
  "meta": {
    "/etc/shadow": {"mode":"0640","gname":"shadow"},
    "/root": {"mode":"0700"},
    "/var/www/html": {"uname":"www-data","gname":"www-data","uid":33,"gid":33}
  },
  "dirs": [{"path":"/tmp","mode":"1777"},{"path":"/usr/bin"},{"path":"/var/log"}],
  "links": [{"path":"/bin/sh","target":"/usr/bin/bash"}],
  "binaries": [{"dir":"/usr/bin","names":["bash","ls"],"mode":"0755","size":1234567}]
}`

func testFS(t *testing.T) *FS {
	t.Helper()
	m := fstest.MapFS{
		"fakeroot/manifest.json":      {Data: []byte(testManifest)},
		"fakeroot/etc/passwd":         {Data: []byte("root:x:0:0:root:/root:/bin/bash\n")},
		"fakeroot/etc/shadow":         {Data: []byte("root:!:19800:0:99999:7:::\n")},
		"fakeroot/root/.bashrc":       {Data: []byte("# ~/.bashrc\n")},
		"fakeroot/var/www/html/x.php": {Data: []byte("<?php\n")},
	}
	f, err := Load(m, "fakeroot", nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

func TestContentAndSizeAgree(t *testing.T) {
	s := testFS(t).NewSession("/")
	body, err := s.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "root:x:0:0:root:/root:/bin/bash\n" {
		t.Fatalf("passwd body: %q", body)
	}
	n, _ := s.Stat("/etc/passwd")
	if n.Size() != int64(len(body)) {
		t.Fatalf("size %d != content len %d", n.Size(), len(body))
	}
}

func TestMetadataOverrides(t *testing.T) {
	s := testFS(t).NewSession("/")
	shadow, _ := s.Stat("/etc/shadow")
	if shadow.Mode().Perm() != 0o640 {
		t.Fatalf("shadow mode %v", shadow.Mode().Perm())
	}
	if shadow.Gname() != "shadow" {
		t.Fatalf("shadow gname %q", shadow.Gname())
	}
	root, _ := s.Stat("/root")
	if !root.IsDir() || root.Mode().Perm() != 0o700 {
		t.Fatalf("root mode %v dir=%v", root.Mode().Perm(), root.IsDir())
	}
	if root.Size() != 4096 {
		t.Fatalf("dir size %d, want 4096", root.Size())
	}
	www, _ := s.Stat("/var/www/html")
	if www.Uname() != "www-data" || www.Uid() != 33 {
		t.Fatalf("www owner %s/%d", www.Uname(), www.Uid())
	}
	tmp, _ := s.Stat("/tmp")
	if tmp.Mode()&fs.ModeSticky == 0 {
		t.Fatalf("tmp missing sticky bit: %v", tmp.Mode())
	}
}

func TestStubBinaryELF(t *testing.T) {
	s := testFS(t).NewSession("/")
	bash, err := s.Stat("/usr/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	if bash.Size() != 1234567 {
		t.Fatalf("stub size %d", bash.Size())
	}
	body, _ := s.ReadFile("/usr/bin/bash")
	if !bytes.HasPrefix(body, []byte("\x7fELF")) {
		t.Fatalf("stub not ELF: % x", body[:4])
	}
}

func TestSymlinkResolution(t *testing.T) {
	s := testFS(t).NewSession("/")
	link, _ := s.Lstat("/bin/sh")
	if !link.IsLink() || link.LinkTarget() != "/usr/bin/bash" {
		t.Fatalf("lstat /bin/sh: link=%v target=%q", link.IsLink(), link.LinkTarget())
	}
	target, err := s.Stat("/bin/sh") // follows the link
	if err != nil {
		t.Fatal(err)
	}
	if target.IsLink() {
		t.Fatal("stat should have followed the symlink")
	}
	if !bytes.HasPrefix(target.Content(), []byte("\x7fELF")) {
		t.Fatal("symlink did not resolve to the bash stub")
	}
}

func TestReadDirSortedAndDeterministic(t *testing.T) {
	s := testFS(t).NewSession("/")
	first := names(t, s, "/etc")
	second := names(t, s, "/etc")
	if len(first) != 2 || first[0] != "passwd" || first[1] != "shadow" {
		t.Fatalf("etc listing: %v", first)
	}
	if !equal(first, second) {
		t.Fatalf("listing not deterministic: %v vs %v", first, second)
	}
}

func TestCwdAndChdir(t *testing.T) {
	s := testFS(t).NewSession("/root")
	if s.Cwd() != "/root" {
		t.Fatalf("cwd %q", s.Cwd())
	}
	if s.Resolve("..") != "/" {
		t.Fatalf("resolve .. = %q", s.Resolve(".."))
	}
	if err := s.Chdir("/etc"); err != nil {
		t.Fatal(err)
	}
	if s.Cwd() != "/etc" {
		t.Fatalf("after chdir cwd %q", s.Cwd())
	}
	if err := s.Chdir("/nope"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("chdir missing dir: %v", err)
	}
	if err := s.Chdir("/etc/passwd"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("chdir into file: %v", err)
	}
}

func TestCopyOnWriteOverlay(t *testing.T) {
	f := testFS(t)
	s := f.NewSession("/")

	if err := s.WriteFile("/tmp/payload.sh", []byte("#!/bin/sh\n")); err != nil {
		t.Fatal(err)
	}
	body, err := s.ReadFile("/tmp/payload.sh")
	if err != nil || string(body) != "#!/bin/sh\n" {
		t.Fatalf("overlay read: %q %v", body, err)
	}
	if !contains(names(t, s, "/tmp"), "payload.sh") {
		t.Fatal("overlay file missing from ls")
	}

	if err := s.Mkdir("/tmp/d"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Stat("/tmp/d"); d == nil || !d.IsDir() {
		t.Fatal("overlay mkdir not a dir")
	}

	// Removing a base file tombstones it for this session only.
	if err := s.Remove("/etc/passwd"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat("/etc/passwd"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("removed file still visible: %v", err)
	}
	if contains(names(t, s, "/etc"), "passwd") {
		t.Fatal("removed file still in ls")
	}

	// A second session is unaffected by the first's mutations.
	other := f.NewSession("/")
	if _, err := other.ReadFile("/etc/passwd"); err != nil {
		t.Fatalf("base mutated across sessions: %v", err)
	}
	if other.Exists("/tmp/payload.sh") {
		t.Fatal("overlay leaked across sessions")
	}
}

func TestMissingPaths(t *testing.T) {
	s := testFS(t).NewSession("/")
	if _, err := s.ReadFile("/etc/nope"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := s.ReadFile("/etc/passwd/x"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("path through a file: %v", err)
	}
	if _, err := s.ReadFile("/etc"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("read a dir: %v", err)
	}
}

// ---- helpers ----

func names(t *testing.T, s *Session, dir string) []string {
	t.Helper()
	ns, err := s.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.Name()
	}
	return out
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
