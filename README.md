# fanta-tennis-exe-patcher

[![Go Version](https://img.shields.io/badge/go-1.27%2B-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S4V328HBWR)

Reads and applies the known binary patches to `FantaTennis.exe`:

- **Cookie refill URL** (`refillUrl`) — the URL the game's cookie refill
  requests point at.
- **Register URL** (`registerUrl`) — the URL the game's registration
  agreement page points at.
- **Reset password URL** (`resetPasswordUrl`) — the URL the game's
  forgot-password page points at.
- **Custom DLL load** (`customDll`) — whether the game loads the custom
  dll, and under which file name it loads it.

## Install

```sh
go install github.com/icyzyy/fanta-tennis-exe-patcher/cmd/fanta-tennis-exe-patcher@latest
```

## Usage

| Command | Effect |
|---|---|
| `fanta-tennis-exe-patcher show <exe>` | Print the current patch settings |
| `fanta-tennis-exe-patcher refill-url <exe> [url]` | Print or set the cookie refill URL |
| `fanta-tennis-exe-patcher register-url <exe> [url]` | Print or set the register URL |
| `fanta-tennis-exe-patcher resetpw-url <exe> [url]` | Print or set the reset-password URL |
| `fanta-tennis-exe-patcher noload [--enable] <exe>` | Disable (default) or enable the custom dll load |
| `fanta-tennis-exe-patcher dll-name <exe> [new-name]` | Print or rename the dll the game loads |

Each setting prints as `<id>\t<state>\t<value>`, where `state` is
`editable` or the reason the setting could not be resolved. The
`customDll` row carries the dll name as a fourth column. An apply also
prints the md5 of the written file and every backup it created:

```console
$ fanta-tennis-exe-patcher show FantaTennis.exe
refillUrl	editable	https://gamefaqs.gamespot.com/
registerUrl	editable	http://visa.mysquare.in.th/agreement.asp
resetPasswordUrl	editable	http://visa.mysquare.in.th/forgot_visa.asp
customDll	editable	disabled	fanta.dll

$ fanta-tennis-exe-patcher refill-url FantaTennis.exe https://example.com/
refillUrl	editable	https://example.com/
md5: 42209da9916cb0f7a897c6380232be52
backup: FantaTennis.exe.bak
backup: FantaTennis.exe.bak.20261013-000141

$ fanta-tennis-exe-patcher register-url FantaTennis.exe https://example.com/reg
registerUrl	editable	https://example.com/reg
md5: 606867091eeaa5475410ba08b57c2d14
backup: FantaTennis.exe.bak.20261013-000143
```

Exit codes: `0` success, `1` runtime error (unreadable file, unresolvable
setting, rejected value), `2` usage error.

## Renaming the custom dll

`dll-name <exe> <new-name>` rewrites the file name the game builds for
its custom dll load. Names must be 1–9 characters from `A-Za-z0-9._-`,
have a non-empty base name, and end in `.dll` (compared
case-insensitively; the name is written as given). The current name is
decoded from the exe first and an undecodable build is refused before
anything is written. Renaming works whether the load is currently
enabled or disabled.

## Backups

Every apply writes backups next to the target before modifying it:

- `<path>.bak` — a pristine copy, created once if absent and never
  overwritten (the first apply owns it).
- `<path>.bak.<timestamp>` — a snapshot of the file as it was at the start
  of that run, at most one per path per process, also never overwritten.

Restore by copying the `.bak` back over the exe.

## Unmatched builds

If a setting prints a reason instead of `editable`, that build doesn't
match the known layout — the tool never guesses. No bytes are written for
a setting it can't resolve.

## Provenance

The CLI is ported from the client's two patch scripts, `patch_url.go` and
`patch_noload.go`.

## License

MIT — see [LICENSE](LICENSE).
