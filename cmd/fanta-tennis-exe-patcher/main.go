// Command fanta-tennis-exe-patcher reads and applies the known binary
// patches to FantaTennis.exe: it lists the current patch settings, sets
// the cookie refill, register and reset-password URLs, disables or
// enables the Custom DLL load, and reads or renames the dll the game
// loads.
//
// Usage:
//
//	fanta-tennis-exe-patcher show <exe>
//	fanta-tennis-exe-patcher refill-url <exe> [new-url]
//	fanta-tennis-exe-patcher register-url <exe> [new-url]
//	fanta-tennis-exe-patcher resetpw-url <exe> [new-url]
//	fanta-tennis-exe-patcher noload [--enable] <exe>
//	fanta-tennis-exe-patcher dll-name <exe> [new-name]
//
// run(args, out) is the entire CLI behind main. It returns 0 on success,
// 1 on runtime errors (unreadable file, unresolvable setting, rejected
// value) and 2 on usage errors. All output, usage and error text
// included, is written to out, so tests pass a single buffer for both
// streams.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/icyzyy/fanta-tennis-exe-patcher/exepatch"
)

// Setting IDs and customDll values; the strings are fixed by the exepatch
// package (whose matching constants stay unexported).
const (
	settingRefillURL   = "refillUrl"
	settingRegisterURL = "registerUrl"
	settingResetPwURL  = "resetPasswordUrl"
	settingCustomDll   = "customDll"
	customDllEnabled   = "enabled"
	customDllDisabled  = "disabled"
)

// usageText is printed after every usage error, and after a bare
// invocation.
const usageText = `usage: fanta-tennis-exe-patcher <command> [arguments]

commands:
  show <exe>                    print the current patch settings
  refill-url <exe> [new-url]    print or set the cookie refill URL
  register-url <exe> [new-url]  print or set the register URL
  resetpw-url <exe> [new-url]   print or set the reset-password URL
  noload [--enable] <exe>       disable or enable the Custom DLL load
  dll-name <exe> [new-name]     print or rename the custom dll
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run is the whole CLI: it dispatches args to a subcommand against
// exepatch.DefaultAnchors, returning 0 on success, 1 on runtime errors
// and 2 on usage errors, writing all output (including usage and error
// text) to out.
func run(args []string, out io.Writer) int {
	if len(args) == 0 {
		return usage(out, "")
	}
	switch args[0] {
	case "show":
		if len(args) != 2 {
			return usage(out, "show requires exactly one <exe> argument")
		}
		return cmdShow(args[1], out)
	case "refill-url", "register-url", "resetpw-url":
		if len(args) < 2 || len(args) > 3 {
			return usage(out, args[0]+" requires <exe> and an optional new-url")
		}
		// An explicit empty string is a value to reject (exit 1), not a
		// missing argument, so presence is tracked separately.
		set := len(args) == 3
		newURL := ""
		if set {
			newURL = args[2]
		}
		return cmdURL(args[1], urlSettingID(args[0]), newURL, set, out)
	case "noload":
		rest := args[1:]
		enable := false
		if len(rest) > 0 && rest[0] == "--enable" {
			enable = true
			rest = rest[1:]
		}
		if len(rest) != 1 {
			return usage(out, "noload requires exactly one <exe> argument (after --enable)")
		}
		return cmdNoload(rest[0], enable, out)
	case "dll-name":
		if len(args) < 2 || len(args) > 3 {
			return usage(out, "dll-name requires <exe> and an optional new-name")
		}
		// An explicit empty string is a name to reject (exit 1), not a
		// missing argument, so presence is tracked separately.
		set := len(args) == 3
		newName := ""
		if set {
			newName = args[2]
		}
		return cmdDllName(args[1], newName, set, out)
	default:
		return usage(out, fmt.Sprintf("unknown subcommand %q", args[0]))
	}
}

// usage prints an optional message followed by the usage text and reports
// the usage-error exit code.
func usage(out io.Writer, msg string) int {
	if msg != "" {
		fmt.Fprintln(out, msg)
	}
	fmt.Fprint(out, usageText)
	return 2
}

// cmdShow opens path and prints one line per setting.
func cmdShow(path string, out io.Writer) int {
	e, err := exepatch.OpenExe(path, exepatch.DefaultAnchors())
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	for _, s := range e.Settings() {
		if s.ID == settingCustomDll {
			printCustomDllSetting(out, e)
			continue
		}
		printSetting(out, s)
	}
	return 0
}

// urlSettingID maps a URL subcommand to the setting ID it edits.
func urlSettingID(cmd string) string {
	switch cmd {
	case "register-url":
		return settingRegisterURL
	case "resetpw-url":
		return settingResetPwURL
	default:
		return settingRefillURL
	}
}

// cmdURL prints the current state of the given URL setting and, when set
// is true, applies newURL and reports the new state, the written file's
// md5, and the backup files the apply created.
func cmdURL(path, id, newURL string, set bool, out io.Writer) int {
	e, err := exepatch.OpenExe(path, exepatch.DefaultAnchors())
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	printSetting(out, settingByID(e.Settings(), id))
	if !set {
		return 0
	}
	return applySetting(e, path, id, newURL, out)
}

// cmdNoload prints the current customDll state and applies the disable (or,
// with enable, the enable) value the same way cmdURL applies a URL.
func cmdNoload(path string, enable bool, out io.Writer) int {
	value := customDllDisabled
	if enable {
		value = customDllEnabled
	}
	e, err := exepatch.OpenExe(path, exepatch.DefaultAnchors())
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	printCustomDllSetting(out, e)
	return applySetting(e, path, settingCustomDll, value, out)
}

// cmdDllName prints the current customDll state with the dll name the
// code cave spells and, when set is true, renames the loaded dll to
// newName, reporting the new state, the written file's md5, and the
// backup files the rename created.
func cmdDllName(path, newName string, set bool, out io.Writer) int {
	e, err := exepatch.OpenExe(path, exepatch.DefaultAnchors())
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	printCustomDllSetting(out, e)
	if !set {
		return 0
	}
	before := backupPaths(path)
	md5After, err := e.RenameCustomDll(newName)
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	printCustomDllSetting(out, e)
	fmt.Fprintf(out, "md5: %s\n", md5After)
	for _, p := range newBackups(path, before) {
		fmt.Fprintf(out, "backup: %s\n", p)
	}
	return 0
}

// applySetting applies value to the given setting and, on success, prints
// the new state, the hex md5 of the written bytes, and every backup file
// that appeared next to path; on failure it prints the error. Exit codes:
// 1 on error, 0 on success. The customDll row keeps its fourth dll-name
// column, so it is printed through printCustomDllSetting.
func applySetting(e *exepatch.Exe, path, id, value string, out io.Writer) int {
	before := backupPaths(path)
	md5After, err := e.Apply(id, value)
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	if id == settingCustomDll {
		printCustomDllSetting(out, e)
	} else {
		printSetting(out, settingByID(e.Settings(), id))
	}
	fmt.Fprintf(out, "md5: %s\n", md5After)
	for _, p := range newBackups(path, before) {
		fmt.Fprintf(out, "backup: %s\n", p)
	}
	return 0
}

// printSetting writes one setting as `<id>\t<editable|reason>\t<value>`;
// an editable setting shows the literal word "editable", a disabled one
// shows why (its Value is empty then).
func printSetting(out io.Writer, s exepatch.Setting) {
	state := s.Reason
	if s.Editable {
		state = "editable"
	}
	fmt.Fprintf(out, "%s\t%s\t%s\n", s.ID, state, s.Value)
}

// printCustomDllSetting writes the customDll setting row with the dll
// name the code cave spells as a fourth column ("unknown" when the name
// pushes do not decode).
func printCustomDllSetting(out io.Writer, e *exepatch.Exe) {
	s := settingByID(e.Settings(), settingCustomDll)
	state := s.Reason
	if s.Editable {
		state = "editable"
	}
	name := "unknown"
	if n, err := e.CustomDllName(); err == nil {
		name = n
	}
	fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", s.ID, state, s.Value, name)
}

// settingByID returns the setting with the given ID. Settings always
// yields all four known IDs, so the zero value is unreachable.
func settingByID(settings []exepatch.Setting, id string) exepatch.Setting {
	for _, s := range settings {
		if s.ID == id {
			return s
		}
	}
	return exepatch.Setting{}
}

// backupPaths returns the backup files that exist next to path right
// now: the pristine <path>.bak and any timestamped <path>.bak.<stamp>
// snapshots. The library writes them as side effects of a successful
// Apply; the CLI only observes them through the filesystem. The
// timestamped ones are found with a directory listing plus a literal
// prefix match, not filepath.Glob: user paths may contain glob
// metacharacters (e.g. a directory named "[FT]", a well-formed
// character class that silently matches nothing, or an unmatched "["
// that errors with ErrBadPattern), which would lose or misattribute
// backup lines.
func backupPaths(path string) map[string]bool {
	set := map[string]bool{}
	if _, err := os.Stat(path + ".bak"); err == nil {
		set[path+".bak"] = true
	}
	dir := filepath.Dir(path)
	prefix := filepath.Base(path) + ".bak."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return set
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			set[filepath.Join(dir, e.Name())] = true
		}
	}
	return set
}

// newBackups returns the sorted backup paths that exist next to path but
// were absent from before.
func newBackups(path string, before map[string]bool) []string {
	var added []string
	for p := range backupPaths(path) {
		if !before[p] {
			added = append(added, p)
		}
	}
	sort.Strings(added)
	return added
}
