package exepatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// backupNow is a fixed timestamp used by every backup test: the stamped
// file name it must produce is 20261011-150405.
var backupNow = time.Date(2026, 10, 11, 15, 4, 5, 0, time.UTC)

// writeBackupFixture creates path with content and returns it.
func writeBackupFixture(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

// readBackupFile returns the content of path, failing the test if unreadable.
func readBackupFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return string(data)
}

// snapshotFiles lists every `.bak.<ts>` file in dir for the given base path.
func snapshotFiles(t *testing.T, dir, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	var found []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filepath.Base(path)+".bak.") {
			found = append(found, e.Name())
		}
	}
	return found
}

func TestEnsureBackupsCreatesBakWhenAbsent(t *testing.T) {
	resetSessionForTest()
	dir := t.TempDir()
	path := writeBackupFixture(t, filepath.Join(dir, "FantaTennis.exe"), "original exe bytes")

	if err := ensureBackups(path, backupNow); err != nil {
		t.Fatalf("ensureBackups: %v", err)
	}
	if got := readBackupFile(t, path+".bak"); got != "original exe bytes" {
		t.Errorf(".bak content = %q, want %q", got, "original exe bytes")
	}
	if got := readBackupFile(t, path+".bak.20261011-150405"); got != "original exe bytes" {
		t.Errorf(".bak.20261011-150405 content = %q, want %q", got, "original exe bytes")
	}
}

func TestEnsureBackupsNeverOverwritesExistingBak(t *testing.T) {
	resetSessionForTest()
	dir := t.TempDir()
	path := writeBackupFixture(t, filepath.Join(dir, "FantaTennis.exe"), "current bytes")
	writeBackupFixture(t, path+".bak", "older backup bytes")

	if err := ensureBackups(path, backupNow); err != nil {
		t.Fatalf("ensureBackups: %v", err)
	}
	if got := readBackupFile(t, path+".bak"); got != "older backup bytes" {
		t.Errorf(".bak content = %q, want %q (must never be overwritten)", got, "older backup bytes")
	}
	if _, err := os.Stat(path + ".bak.20261011-150405"); err != nil {
		t.Errorf("timestamped snapshot missing: %v", err)
	}
}

func TestEnsureBackupsSkipsExistingSnapshot(t *testing.T) {
	resetSessionForTest()
	dir := t.TempDir()
	path := writeBackupFixture(t, filepath.Join(dir, "FantaTennis.exe"), "current bytes")
	writeBackupFixture(t, path+".bak.20261011-150405", "prior session snapshot")

	if err := ensureBackups(path, backupNow); err != nil {
		t.Fatalf("ensureBackups: %v", err)
	}
	if got := readBackupFile(t, path+".bak.20261011-150405"); got != "prior session snapshot" {
		t.Errorf("snapshot content = %q, want %q (must not be rewritten)", got, "prior session snapshot")
	}
	if got := readBackupFile(t, path+".bak"); got != "current bytes" {
		t.Errorf(".bak content = %q, want %q", got, "current bytes")
	}
}

func TestEnsureBackupsOneSnapshotPerSession(t *testing.T) {
	resetSessionForTest()
	dir := t.TempDir()
	path := writeBackupFixture(t, filepath.Join(dir, "FantaTennis.exe"), "exe bytes")

	if err := ensureBackups(path, backupNow); err != nil {
		t.Fatalf("first ensureBackups: %v", err)
	}
	later := backupNow.Add(time.Hour)
	if err := ensureBackups(path, later); err != nil {
		t.Fatalf("second ensureBackups: %v", err)
	}
	if snaps := snapshotFiles(t, dir, path); len(snaps) != 1 {
		t.Errorf("snapshot count = %d (%v), want exactly 1", len(snaps), snaps)
	}
}

func TestEnsureBackupsSeparatePathsIndependent(t *testing.T) {
	resetSessionForTest()
	dir := t.TempDir()
	a := writeBackupFixture(t, filepath.Join(dir, "a.exe"), "a bytes")
	b := writeBackupFixture(t, filepath.Join(dir, "b.exe"), "b bytes")

	// Same second, two paths: both must get their own snapshot.
	if err := ensureBackups(a, backupNow); err != nil {
		t.Fatalf("ensureBackups(a): %v", err)
	}
	if err := ensureBackups(b, backupNow); err != nil {
		t.Fatalf("ensureBackups(b): %v", err)
	}
	if _, err := os.Stat(a + ".bak.20261011-150405"); err != nil {
		t.Errorf("a snapshot missing: %v", err)
	}
	if _, err := os.Stat(b + ".bak.20261011-150405"); err != nil {
		t.Errorf("b snapshot missing: %v", err)
	}
}

// TestCopyExclusiveRemovesPartialDstOnCopyFailure pins that a copy that
// fails after the exclusive create never leaves a truncated dst behind:
// the src is a directory (os.Open succeeds, io.Copy fails with EISDIR on
// Linux), so the failure is deterministic.
func TestCopyExclusiveRemovesPartialDstOnCopyFailure(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "srcdir")
	if err := os.Mkdir(srcDir, 0o755); err != nil {
		t.Fatalf("Mkdir(%s): %v", srcDir, err)
	}
	dst := filepath.Join(dir, "FantaTennis.exe.bak")

	err := copyExclusive(srcDir, dst)
	if err == nil {
		t.Fatal("copyExclusive(dir, dst) error = nil, want the EISDIR copy failure")
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Errorf("partial dst left behind after failed copy: %v", statErr)
	}
}

// TestEnsureBackupsDedupesCleanedPaths pins that the per-session snapshot
// registry keys on filepath.Clean(path): different spellings of the same
// file (./x.exe, sub/../x.exe) must produce exactly one timestamped
// snapshot, while all file operations keep using the caller's path.
func TestEnsureBackupsDedupesCleanedPaths(t *testing.T) {
	resetSessionForTest()
	dir := t.TempDir()
	path := writeBackupFixture(t, filepath.Join(dir, "x.exe"), "exe bytes")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("Mkdir(sub): %v", err)
	}
	spellings := []string{
		path,                  // dir/x.exe
		dir + "/./x.exe",      // dir/./x.exe
		dir + "/sub/../x.exe", // dir/sub/../x.exe
	}
	for i, spelling := range spellings {
		if err := ensureBackups(spelling, backupNow.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("ensureBackups(%q): %v", spelling, err)
		}
	}
	if snaps := snapshotFiles(t, dir, path); len(snaps) != 1 {
		t.Errorf("snapshot count = %d (%v), want exactly 1 for three spellings of the same file", len(snaps), snaps)
	}
}
