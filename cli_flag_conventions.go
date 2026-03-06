package main

import (
	"fmt"
	"strconv"
	"strings"

	flag "github.com/spf13/pflag"
)

// applyCommandFlagConventions augments command-local flag sets with a consistent
// long/short alias policy while preserving existing flag names for compatibility.
func applyCommandFlagConventions(fs *flag.FlagSet) {
	if fs == nil {
		return
	}

	// Legacy short-only flags used across Forge commands.
	addLongAliasForLegacyFlag(fs, "v", "verbose")
	addLongAliasForLegacyFlag(fs, "w", "workers")

	// Preferred short aliases for common long flags.
	addHiddenShorthandAlias(fs, "db", "d")
	addHiddenShorthandAlias(fs, "path", "p")
	addHiddenShorthandAlias(fs, "config", "c")
	addHiddenShorthandAlias(fs, "limit", "n")
	addHiddenShorthandAlias(fs, "from", "f")
	addHiddenShorthandAlias(fs, "to", "t")
	addHiddenShorthandAlias(fs, "strict", "s")
	addHiddenShorthandAlias(fs, "basic-tree", "b")
	addHiddenShorthandAlias(fs, "recursive", "r")
	addHiddenShorthandAlias(fs, "tags", "t")
	addHiddenShorthandAlias(fs, "tree", "T")
	addHiddenShorthandAlias(fs, "apply", "a")
	addHiddenShorthandAlias(fs, "kind", "k")
	addHiddenShorthandAlias(fs, "algo", "a")
	addHiddenShorthandAlias(fs, "digest", "g")
	addHiddenShorthandAlias(fs, "blake3", "b")
	addHiddenShorthandAlias(fs, "name", "n")
	addHiddenShorthandAlias(fs, "public-key", "k")
	addHiddenShorthandAlias(fs, "roles", "r")

	// Prefer `-o` for `out` where available; otherwise use it for `output`.
	if fs.Lookup("out") != nil {
		addHiddenShorthandAlias(fs, "out", "o")
	} else {
		addHiddenShorthandAlias(fs, "output", "o")
	}
}

func addLongAliasForLegacyFlag(fs *flag.FlagSet, legacyName string, longName string) {
	legacy := fs.Lookup(legacyName)
	if legacy == nil {
		return
	}
	if fs.Lookup(longName) != nil {
		return
	}
	alias := fs.VarPF(legacy.Value, longName, "", legacy.Usage)
	if alias == nil {
		return
	}
	alias.DefValue = legacy.DefValue
	alias.NoOptDefVal = legacy.NoOptDefVal
}

func addHiddenShorthandAlias(fs *flag.FlagSet, name string, shorthand string) {
	if len(strings.TrimSpace(shorthand)) != 1 {
		return
	}
	target := fs.Lookup(name)
	if target == nil {
		return
	}
	if fs.ShorthandLookup(shorthand) != nil {
		return
	}

	aliasName := fmt.Sprintf("__%s_short_%s", strings.ReplaceAll(name, "-", "_"), shorthand)
	if fs.Lookup(aliasName) != nil {
		return
	}

	alias := fs.VarPF(target.Value, aliasName, shorthand, target.Usage)
	if alias == nil {
		return
	}
	alias.Hidden = true
	alias.DefValue = target.DefValue
	alias.NoOptDefVal = target.NoOptDefVal
}

// normalizePFlagArgs preserves Forge's historical single-dash long-flag
// compatibility (e.g. "-db", "-output") by rewriting those tokens to
// pflag-compatible "--db", "--output" before parsing.
func normalizePFlagArgs(fs *flag.FlagSet, args []string) []string {
	if fs == nil || len(args) == 0 {
		return args
	}

	out := make([]string, 0, len(args))
	passthrough := false
	for _, arg := range args {
		if passthrough {
			out = append(out, arg)
			continue
		}
		if arg == "--" {
			passthrough = true
			out = append(out, arg)
			continue
		}
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || arg == "-" {
			out = append(out, arg)
			continue
		}
		if looksLikeNegativeNumber(arg) {
			out = append(out, arg)
			continue
		}

		withoutDash := arg[1:]
		name := withoutDash
		if idx := strings.IndexByte(withoutDash, '='); idx >= 0 {
			name = withoutDash[:idx]
		}
		if len(name) <= 1 {
			out = append(out, arg)
			continue
		}
		if fs.Lookup(name) == nil {
			out = append(out, arg)
			continue
		}

		out = append(out, "--"+withoutDash)
	}
	return out
}

func looksLikeNegativeNumber(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	_, err := strconv.ParseFloat(arg, 64)
	return err == nil
}
