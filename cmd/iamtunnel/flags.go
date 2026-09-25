package main

import (
	"fmt"
	"strings"
)

// The flag grammar is one and the same for every command: flags come
// after the subcommand word, long names with two dashes, "--name value"
// or "--name=value", boolean flags take no value (or =true/=false),
// "--" ends the flags, and -h/--help prints the help of the nearest
// command level. Unknown flags and values are rejected before anything
// runs.

type flagKind int

const (
	kindBool flagKind = iota
	kindValue
)

// flagSet parses the arguments of one leaf command.
type flagSet struct {
	name     string // command path, e.g. "gateway run"
	usage    string // full usage line for error messages
	argNames string // positional part of the usage, e.g. "<machine>"
	specs    map[string]flagKind
	vals     map[string]string
	help     bool
	pos      []string
	noMore   bool // seen "--"; the rest is positional
}

func newFlagSet(name, argNames string) *flagSet {
	return &flagSet{
		name:     name,
		usage:    strings.TrimRight("iamtunnel "+name+" "+argNames, " "),
		argNames: argNames,
		specs:    map[string]flagKind{"help": kindBool},
		vals:     map[string]string{},
	}
}

// boolFlag registers a boolean flag (besides the automatic --help).
func (f *flagSet) boolFlag(name string) { f.specs[name] = kindBool }

// valFlag registers a flag that takes a value.
func (f *flagSet) valFlag(name string) { f.specs[name] = kindValue }

// allowed lists the flags for error messages, without --help.
func (f *flagSet) allowed() string {
	names := make([]string, 0, len(f.specs))
	for n, k := range f.specs {
		if n == "help" {
			continue
		}
		if k == kindValue {
			names = append(names, "--"+n+" <value>")
		} else {
			names = append(names, "--"+n)
		}
	}
	return strings.Join(names, ", ")
}

func (f *flagSet) parse(args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if f.noMore {
			f.pos = append(f.pos, a)
			continue
		}
		switch {
		case a == "--":
			f.noMore = true
		case a == "-h" || a == "--help":
			f.help = true
		case strings.HasPrefix(a, "--"):
			body := a[2:]
			name, value, hasValue := strings.Cut(body, "=")
			kind, known := f.specs[name]
			if !known {
				return userErrf("iamtunnel %s: unknown flag %q — allowed flags: %s. See \"iamtunnel %s --help\".", f.name, a, f.allowed(), f.name)
			}
			if kind == kindBool {
				if !hasValue {
					f.set(name, "true")
					continue
				}
				switch value {
				case "true", "false":
					f.set(name, value)
				default:
					return userErrf("iamtunnel %s: flag --%s takes no value or =true/=false, got %q.", f.name, name, value)
				}
				continue
			}
			if hasValue {
				f.set(name, value)
				continue
			}
			if i+1 >= len(args) {
				return userErrf("iamtunnel %s: flag --%s needs a value — usage: --%s <value>.", f.name, name, name)
			}
			i++
			f.set(name, args[i])
		case strings.HasPrefix(a, "-") && len(a) > 1:
			return userErrf("iamtunnel %s: unknown flag %q — flags use two dashes (%s). See \"iamtunnel %s --help\".", f.name, a, f.allowed(), f.name)
		default:
			f.pos = append(f.pos, a)
		}
	}
	return nil
}

func (f *flagSet) set(name, v string) {
	f.vals[name] = v
	if name == "help" && v == "true" {
		f.help = true
	}
}

// has reports whether the boolean flag stands true.
func (f *flagSet) has(name string) bool { return f.vals[name] == "true" }

// val returns the value of a value-taking flag, "" when unset.
func (f *flagSet) val(name string) string { return f.vals[name] }

// wantN checks the positional count against n and names the problem the
// way the person can fix it: what is missing or which argument is extra.
func (f *flagSet) wantN(n int) error {
	howMany := "exactly one"
	if n != 1 {
		howMany = fmt.Sprintf("exactly %d", n)
	}
	if len(f.pos) == n {
		return nil
	}
	if len(f.pos) < n {
		return userErrf("iamtunnel %s: missing required argument %s — want %s: usage: %s.", f.name, f.argNames, howMany, f.usage)
	}
	return userErrf("iamtunnel %s: unexpected argument %q — want %s argument(s), %s: usage: %s.", f.name, f.pos[n], howMany, f.argNames, f.usage)
}

// wantNone is wantN(0) with its own wording for commands without
// positionals.
func (f *flagSet) wantNone() error {
	if len(f.pos) == 0 {
		return nil
	}
	return userErrf("iamtunnel %s: unexpected argument %q — this command takes no positional arguments: usage: %s.", f.name, f.pos[0], f.usage)
}
