# fanta-tennis-exe-patcher — agent instructions

Go 1.27.1, standard library only (no third-party `require` — keep it that
way). Two packages: `exepatch` (library) and `cmd/fanta-tennis-exe-patcher`
(CLI). User-facing behavior is documented in `README.md`; this file covers
what an agent would otherwise get wrong.

Machine-specific paths and pointers (game install location, provenance
scripts, design doc) live in `AGENTS.local.md` when present; it is
untracked and never committed.

## Commands

- `make test` / `go test ./...` — unit tests (always run before committing)
- `make vet` / `make fmt` — `go vet` and the `gofmt -l .` gate
- Focused test: `go test ./exepatch/ -run TestApplyURL -v` (regex over
  test names)

Full gate, all four clean (`gofmt -l .` prints nothing) before claiming
anything works:

```
go build ./... && go test -count=1 ./... && go vet ./... && gofmt -l .
```

All four must be clean (`gofmt -l .` prints nothing). Focused test:
`go test ./exepatch/ -run TestApplyURL -v` (regex over test names).

Env-gated integration test — SKIPs unless set, must stay read-only:

```
FANTA_EXE_DIR=<dir containing FantaTennis.exe> \
  go test -count=1 ./exepatch/ -run TestIntegrationRealExeReadOnly -v
```

## Read-only zones

- The game install directory (`FANTA_EXE_DIR`) is STRICTLY read-only:
  the integration test only reads + asserts mtimes unchanged; every
  mutation test uses `t.TempDir()` copies. Never write there, never
  "fix" the real `FantaTennis.exe`/`.bak`.
- The provenance scripts this module ported (`patch_url.go`,
  `patch_noload.go`) live in a private companion repo — read them for
  logic history, never edit.
- `.superpowers/` is self-ignored SDD session state, not source.

## Design invariants (tests pin these — do not "clean them up")

- `DefaultAnchors()` is a FUNCTION returning fresh `CustomDllOriginal`/
  `CustomDllNops` slices per call (consumers must not mutate package
  globals). Not a var.
- `Settings()` order is API: `[refillUrl, registerUrl, resetPasswordUrl,
  customDll]`; the editor panel iterates it generically.
- All three URL settings share ONE pipeline (`applyURL`/`resolveURL`
  parameterized by per-ID site anchor); customDll is separate. Fix drift
  by generalizing, never by copying a branch.
- `commit()` uses DIRECT `os.WriteFile` on purpose — not temp+rename.
  The chmod-0444 test requires the write itself to fail on read-only
  files; mid-write-failure recovery is via the backups, not atomicity.
- Backups never overwrite: pristine `<path>.bak` once (O_EXCL), one
  timestamped `<path>.bak.YYYYMMDD-HHMMSS` per process per path
  (registry keyed by `filepath.Clean`).
- Apply validates `http://`/`https://` on write because the reader
  requires an `http` prefix — a looser writer bricks the setting on the
  next read. Keep write-side validation ≥ read-side.
- URL relocation scans `.rdata` zero-gaps with a whole-file pointer
  check over the full `[candVA, candVA+need)` span; the post-write
  verification requires exactly one pointer to the new VA.
- Anchor values (`0x5AE66` refill / `0x5ADB5` register / `0x5AE58`
  reset-pw / `0x2830A7` customDll call site, cave pusha `0x28309A` /
  add-esp `0x2830AE`) are verified ground truth against both real
  binaries — change them only with new byte-level evidence.
- The custom dll name lives in the cave's three stack pushes (imm32 +
  imm32 + imm8, NUL-padded window, ≤ 9 chars). `customDllNameAt` (read)
  and `putCustomDllName` (write) are inverses; `validateCustomDllName`
  (write side: charset + `.dll` suffix) must stay at least as strict as
  the decode charset — a looser writer could produce a name the reader
  rejects, bricking the name on the next read. Renames decode the
  CURRENT name first and refuse undecodable builds before writing.

## Known limitations (surfaced by design review; intentional for now)

- Apply's exactly-one-pointer verification has never run against the real
  exe (integration test is read-only by design) — first Apply on a real
  copy is the project's next-phase watch item; failure is a clean error,
  not corruption.
- Relocation assumes the URL string lives in `.rdata` (true for both
  known builds; `OpenExe` requires the section anyway).

## Git

Commits are the human's call — never `git commit`/`push` unless asked in
the moment. If asked to commit: Conventional Commits + blank line +
`On-behalf-of: Pantakan Chusri-eam <pantakan.c@ku.th>`. This
repo is pre-publication (human pushes to
`github.com/icyzyy/fanta-tennis-exe-patcher`; the editor pins it — no
`replace` directive, ever).

## Context sources

- WHY exists: the exe-patching-mode design doc in the fanta-tennis-editor
  repo (approved design; see `AGENTS.local.md` for the path).
- Real-binary ground truth and offset history: the companion client
  repo's `NOTES.md` (see `AGENTS.local.md` for the path).
