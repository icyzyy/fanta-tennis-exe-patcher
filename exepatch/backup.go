package exepatch

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// backupStampLayout is the layout for the timestamped snapshot suffix:
// `<path>.bak.<YYYYMMDD-HHMMSS>`.
const backupStampLayout = "20060102-150405"

// sessionSnapshots records every cleaned path (filepath.Clean) this
// process has already snapshotted this session, so at most one timestamped
// copy is written per file per run. Guarded by sessionMu.
var (
	sessionMu        sync.Mutex
	sessionSnapshots = map[string]bool{}
)

// resetSessionForTest clears the per-process snapshot registry so tests
// start from a clean session.
func resetSessionForTest() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	sessionSnapshots = map[string]bool{}
}

// ensureBackups applies the backup policy for path: (a) if `<path>.bak` is
// absent, create it from the current file — an existing one is never
// overwritten; (b) if this process has not snapshotted path yet this
// session, write `<path>.bak.<now>` (also never overwriting an existing
// file) and record it in the session registry; (c) path is recorded in the
// session registry even when only (a) ran. The session registry keys on
// filepath.Clean(path), so different spellings of the same file
// (`x.exe`, `./x.exe`, `a/../x.exe`) share one snapshot per session, while
// every file operation still uses the caller's original path. The pristine
// copy is always the first write when both are needed. A failure partway
// leaves partial state; nothing is rolled back (the pristine copy is
// never harmful).
func ensureBackups(path string, now time.Time) error {
	if _, err := os.Stat(path + ".bak"); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := copyExclusive(path, path+".bak"); err != nil {
			return err
		}
	}

	key := filepath.Clean(path)
	sessionMu.Lock()
	needSnapshot := !sessionSnapshots[key]
	sessionMu.Unlock()
	if needSnapshot {
		if err := copyExclusive(path, path+".bak."+now.Format(backupStampLayout)); err != nil {
			return err
		}
	}

	sessionMu.Lock()
	sessionSnapshots[key] = true
	sessionMu.Unlock()
	return nil
}

// copyExclusive copies src to dst, creating dst exclusively: if dst already
// exists it is left untouched and no error is returned. If the copy or the
// final Close fails after dst was created, the partial dst is removed
// best-effort before the error is returned, so a truncated backup is never
// left for a future run to treat as authoritative.
func copyExclusive(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}
