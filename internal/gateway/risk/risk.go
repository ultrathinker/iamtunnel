package risk

import (
	"regexp"
	"strings"
	"unicode"
)

// Level is the consequence-grade of a command — what happens if it
// actually runs on the target machine. The constants carry the
// definition; do not retune them by feel (levels are graded
// by CONSEQUENCE, not by feel).
type Level int

const (
	// Green — reversible and local. Read-only observation, harmless
	// inspection, deletion of obviously-temporary paths. A green
	// verdict may carry `Matched=true` (a rule looked and approved,
	// e.g. `rm -rf /tmp/build`) or `Matched=false` (no rule
	// recognized the command, e.g. `Get-Process`).
	Green Level = iota
	// Yellow — touches state that others depend on, or the rollback
	// costs more than a minute. Examples: `git push --force`,
	// `taskkill /IM nginx.exe`, `reg add HKLM\…`, `curl … | sh`,
	// `sudo …` standing alone. Always `Matched=true`.
	Yellow
	// Red — destroys data or cuts off access.
	// `rm -rf /var/lib/postgresql`, `Remove-Item -Recurse -Force
	// C:\Windows`, `iptables -F`, `Stop-Service sshd`,
	// `DROP DATABASE`, `shutdown`, `chmod -R 777 /`. Always
	// `Matched=true`.
	Red
)

// String returns the kebab-case name of the level, used by tests and
// logs. The values must stay stable — UI and downstream callers key
// off them.
func (l Level) String() string {
	switch l {
	case Red:
		return "red"
	case Yellow:
		return "yellow"
	case Green:
		return "green"
	default:
		return "green"
	}
}

// Verdict is what `Classify` returns for one command. Rule is the
// kebab-case name of the rule that fired (empty when Matched is
// false); Reason is a single short sentence aimed at a person. The
// pair is the wire format of this package's output — keep it stable
// and useful. Reason for the worst Level wins; "ls && rm -rf /var"
// reports the rm reason, not the ls one.
type Verdict struct {
	Level   Level
	Rule    string
	Reason  string
	Matched bool
}

// Classify returns the worst-level verdict across the parts of the
// command. Compound commands (`;`, `&&`, `||`, and `|`, outside
// quotes and outside `{…}` / `(…)` groups) are split first; each part
// is matched against the rule list; the part with the highest level
// wins, and its Rule/Reason are kept. A pipelined `curl … | sh` is
// detected at the whole-command level so the split on `|` cannot
// hide it. The function is safe for concurrent use.
func Classify(command string) Verdict {
	return classifyCommand(command, 0)
}

func classifyCommand(command string, wrapperDepth int) Verdict {
	if v, ok := matchPipeToExec(command); ok {
		return v
	}
	if v, ok := classifyOpaqueCommand(command); ok {
		return v
	}
	parts := splitOnShellOperators(command)
	var worst Verdict // zero; outranked by anything that matched a rule
	for _, p := range parts {
		v := classifyPartAtDepth(p, wrapperDepth)
		if worseThan(v, worst) {
			worst = v
		}
	}
	if !worst.Matched {
		return Verdict{Level: Green, Matched: false}
	}
	return worst
}

// worseThan decides whether a's verdict strictly outranks b's. The
// comparison is on (Level, Matched): same-level unmatched greens
// are the baseline (level 0 in `badness`), a green that a rule
// approved outranks them, and yellow/red always outrank green.
func worseThan(a, b Verdict) bool {
	return badness(a) > badness(b)
}

// badness returns the numerical ranking used by `worseThan`. The
// zero value (`Verdict{}`) sits at the bottom: any rule verdict will
// displace it.
func badness(v Verdict) int {
	if !v.Matched {
		return -1
	}
	switch v.Level {
	case Red:
		return 3
	case Yellow:
		return 2
	case Green:
		return 1
	default:
		return 0
	}
}

// splitOnShellOperators splits `s` on the four shell composition
// operators `;`, `&&`, `||`, and `|`. Quoting is respected at the
// level a textual classifier needs: characters inside matched "…",
// '…', or `…` (PowerShell backtick escape) are not treated as
// separators; characters inside `(…)` or `{…}` groups are not
// separated either, so fork bombs (`{ :|:& }`) survive. The split
// is whitespace-trimmed; empty parts are dropped. The returned
// slice preserves order.
func splitOnShellOperators(s string) []string {
	var parts []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	parenDepth, braceDepth := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Backslash escape outside quotes: copy next char verbatim.
		if c == '\\' && !inSingle && i+1 < len(s) {
			cur.WriteByte(c)
			i++
			cur.WriteByte(s[i])
			continue
		}
		// PowerShell backtick escape: skip the backtick and the next char.
		if c == '`' && !inSingle {
			cur.WriteByte(c)
			i++
			if i < len(s) {
				cur.WriteByte(s[i])
			}
			continue
		}
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
				cur.WriteByte(c)
				continue
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
				cur.WriteByte(c)
				continue
			}
		case '(':
			if !inSingle && !inDouble {
				parenDepth++
			}
		case ')':
			if !inSingle && !inDouble && parenDepth > 0 {
				parenDepth--
			}
		case '{':
			if !inSingle && !inDouble {
				braceDepth++
			}
		case '}':
			if !inSingle && !inDouble && braceDepth > 0 {
				braceDepth--
			}
		}
		if !inSingle && !inDouble && parenDepth == 0 && braceDepth == 0 {
			// Two-character operators first.
			if c == '&' && i+1 < len(s) && s[i+1] == '&' {
				if t := strings.TrimSpace(cur.String()); t != "" {
					parts = append(parts, t)
				}
				cur.Reset()
				i++
				continue
			}
			if c == '|' && i+1 < len(s) && s[i+1] == '|' {
				if t := strings.TrimSpace(cur.String()); t != "" {
					parts = append(parts, t)
				}
				cur.Reset()
				i++
				continue
			}
			if c == ';' || c == '|' {
				if t := strings.TrimSpace(cur.String()); t != "" {
					parts = append(parts, t)
				}
				cur.Reset()
				continue
			}
		}
		cur.WriteByte(c)
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		parts = append(parts, t)
	}
	return parts
}

// classifyPartAtDepth returns the verdict of the first matching rule for one
// shell segment. Red rules are tried first because their outcome dominates
// (ssh service stop is red even though net/stop is a yellow rule); yellow
// rules come next; everything else is unmatched green. An elevator prefix
// (`sudo`, `doas`, `runas`) is handled directly so recursive classification
// can carry the wrapper depth through the inner command.
func classifyPartAtDepth(part string, wrapperDepth int) Verdict {
	if v, ok := classifyOpaqueCommand(part); ok {
		return v
	}
	if v, ok := classifyStdinInterpreter(part); ok {
		return v
	}
	if label, inner, ok := unwrapCommandWrapper(part); ok {
		if wrapperDepth >= maxCommandWrapperDepth {
			return Verdict{
				Level:   Yellow,
				Rule:    "wrapper-depth",
				Reason:  label + ": wrapper nesting exceeds the maximum depth (3)",
				Matched: true,
			}
		}
		if strings.TrimSpace(inner) == "" {
			return Verdict{
				Level:   Yellow,
				Rule:    "wrapper-unreadable",
				Reason:  label + ": the command inside the wrapper is missing and cannot be checked",
				Matched: true,
			}
		}
		return wrapCommandVerdict(label, classifyCommand(inner, wrapperDepth+1))
	}
	if _, has := elevatorCommand(part); has {
		v, _ := ruleSudoAtStartAtDepth(part, wrapperDepth)
		return v
	}
	for _, r := range redRules {
		if v, ok := r(part); ok {
			return v
		}
	}
	for _, r := range yellowRules {
		if v, ok := r(part); ok {
			return v
		}
	}
	return Verdict{Level: Green, Matched: false}
}

const maxCommandWrapperDepth = 3

// ── interpreters reading stdin (R4 F-03) ──

// stdinInterpreterNames are the interpreters whose no-payload launch is a
// command channel: left without a -c/-Command/script argument they read
// their commands from the standard input.
var stdinInterpreterNames = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "ksh": true, "dash": true, "ash": true,
	"python": true, "python3": true, "perl": true, "node": true, "nodejs": true, "ruby": true,
	"powershell": true, "pwsh": true, "cmd": true,
}

// classifyStdinInterpreter flags the launches whose real commands arrive
// on stdin, past every textual rule this package has. `powershell`, `bash`,
// `python -` and friends carry nothing to judge on their command line —
// which is exactly why they were green-unmatched before (R4 F-03) while
// being the shape that turns an exec grant into an unmonitored shell.
// Yellow, not red, for the same reason sudo-at-start is yellow: the loss
// here is of judgment, not of data. Payload forms stay out of this rule:
// -c/-Command bodies go to the unwrapper, -EncodedCommand/-File/-e to the
// opaque rules ahead of it, and a script-file argument is a payload too.
func classifyStdinInterpreter(part string) (Verdict, bool) {
	trimmed := strings.TrimSpace(part)
	first := strings.ToLower(firstWord(trimmed))
	if !stdinInterpreterNames[first] {
		return Verdict{}, false
	}
	rest := restAfterFirst(trimmed)
	var stdin bool
	switch {
	case first == "bash" || first == "sh" || first == "zsh" || first == "ksh" || first == "dash" || first == "ash":
		stdin = posixShellReadsStdin(rest)
	case first == "python" || first == "python3" || first == "perl" || first == "node" || first == "nodejs" || first == "ruby":
		stdin = scriptInterpreterReadsStdin(rest)
	case first == "powershell" || first == "pwsh":
		stdin = powerShellReadsStdin(rest)
	default: // cmd
		stdin = cmdReadsStdin(rest)
	}
	if !stdin {
		return Verdict{}, false
	}
	return Verdict{
		Level:   Yellow,
		Rule:    "stdin-interpreter",
		Reason:  first + " reads commands from the standard input in this form — what arrives on stdin is not checked by the command classifier",
		Matched: true,
	}, true
}

// posixShellReadsStdin: any shell launch with no -c-style flag and no
// script argument reads stdin, flag or bare (`bash -s`, `bash -ls`, `bash
// -l`). A bare `-c` with no payload is the unwrapper's unreadable shell,
// not a stdin form — it stays where it was.
func posixShellReadsStdin(rest string) bool {
	if _, ok := wrapperPayload(rest, "-c", "--command"); ok {
		return false
	}
	if _, ok := wrapperPayloadWithBundledShortFlag(rest, 'c'); ok {
		return false
	}
	for _, tok := range tokens(rest) {
		if !strings.HasPrefix(tok, "-") {
			return false // a script file to run instead
		}
	}
	return true
}

// scriptInterpreterReadsStdin: python/perl/node/ruby run a script file
// when given one and read stdin when not. The -c/-e opaque forms are
// handled ahead of this rule; they are re-checked here only defensively.
func scriptInterpreterReadsStdin(rest string) bool {
	for _, tok := range tokens(rest) {
		lower := strings.ToLower(tok)
		if lower == "-c" || lower == "-e" {
			return false
		}
		if !strings.HasPrefix(tok, "-") {
			return false // a script file to run instead
		}
	}
	return true
}

// powerShellReadsStdin: options-only launch (`powershell -NoProfile`) opens
// an interactive console that reads stdin; `-Command -` reads the commands
// from stdin too. A real -Command payload is the unwrapper's, and a bare
// `-Command` with nothing after it stays the unwrapper's unreadable shell.
func powerShellReadsStdin(rest string) bool {
	inner, ok := wrapperPayloadMatching(rest, isPowerShellCommandFlag)
	if ok {
		return stripCommandQuotes(inner) == "-"
	}
	for _, tok := range tokens(rest) {
		if !strings.HasPrefix(tok, "-") {
			return false // a script file or an inline command to run instead
		}
	}
	return true
}

// cmdReadsStdin: bare `cmd` and option-only forms wait on stdin; `/k` runs
// its tail and then keeps reading stdin. `/c` is the payload form the
// unwrapper owns.
func cmdReadsStdin(rest string) bool {
	for _, tok := range tokens(rest) {
		lower := strings.ToLower(tok)
		if lower == "/k" || lower == "-k" {
			return true
		}
		if lower == "/c" || lower == "-c" {
			return false
		}
		if !strings.HasPrefix(tok, "/") && !strings.HasPrefix(tok, "-") {
			return false // cmd runs the rest as its command line instead
		}
	}
	return true
}

var opaqueBase64PipeRe = regexp.MustCompile(`(?i)\bbase64\b[^\n|]*\s(?:-d|--decode)\b[^\n|]*\|\s*(?:sh|bash|zsh|ksh|dash)\b`)

func wrapCommandVerdict(label string, inner Verdict) Verdict {
	if !inner.Matched || strings.TrimSpace(inner.Reason) == "" {
		return inner
	}
	inner.Reason = label + ": " + inner.Reason
	return inner
}

// unwrapCommandWrapper recognizes textual command evaluators. It returns
// their payload without trying to execute or decode it; the payload is then
// classified recursively by classifyCommand.
func unwrapCommandWrapper(part string) (label, inner string, ok bool) {
	trimmed := strings.TrimSpace(part)
	first := strings.ToLower(firstWord(trimmed))
	rest := restAfterFirst(trimmed)
	switch first {
	case "bash", "sh", "zsh", "ksh", "dash":
		inner, ok = wrapperPayload(rest, "-c", "--command")
		if !ok {
			inner, ok = wrapperPayloadWithBundledShortFlag(rest, 'c')
		}
		if ok {
			return first + " -c", inner, true
		}
	case "powershell", "pwsh":
		inner, ok = wrapperPayloadMatching(rest, isPowerShellCommandFlag)
		if ok {
			return first + " -Command", inner, true
		}
	case "cmd":
		inner, ok = wrapperPayload(rest, "/c", "-c")
		if ok {
			return first + " /c", inner, true
		}
	}

	for _, name := range []string{"invoke-expression", "iex"} {
		if !strings.HasPrefix(strings.ToLower(trimmed), name) {
			continue
		}
		tail := trimmed[len(name):]
		if tail != "" && !unicode.IsSpace(rune(tail[0])) && tail[0] != '(' {
			continue
		}
		tail = strings.TrimSpace(tail)
		if strings.HasPrefix(tail, "(") && strings.HasSuffix(tail, ")") {
			tail = strings.TrimSpace(tail[1 : len(tail)-1])
		}
		return name, stripCommandQuotes(tail), true
	}
	return "", "", false
}

func wrapperPayload(rest string, flags ...string) (string, bool) {
	return wrapperPayloadMatching(rest, func(part string) bool {
		for _, flag := range flags {
			if strings.EqualFold(part, flag) {
				return true
			}
		}
		return false
	})
}

func wrapperPayloadMatching(rest string, matches func(string) bool) (string, bool) {
	parts := tokens(rest)
	for i, part := range parts {
		if matches(part) {
			if i+1 >= len(parts) {
				return "", true
			}
			return stripCommandQuotes(strings.Join(parts[i+1:], " ")), true
		}
	}
	return "", false
}

// wrapperPayloadWithBundledShortFlag recognizes the POSIX shell convention
// where one-letter options are combined in one argument and the command
// option is last: `bash -lc`, `bash -ic`, and `bash -lic` all mean `-c`.
func wrapperPayloadWithBundledShortFlag(rest string, flag byte) (string, bool) {
	return wrapperPayloadMatching(rest, func(part string) bool {
		if len(part) < 2 || part[0] != '-' || part[1] == '-' || part[len(part)-1] != flag {
			return false
		}
		for i := 1; i < len(part)-1; i++ {
			if (part[i] < 'a' || part[i] > 'z') && (part[i] < 'A' || part[i] > 'Z') {
				return false
			}
		}
		return true
	})
}

func powerShellOptionName(arg string) (string, bool) {
	if strings.HasPrefix(arg, "--") {
		arg = arg[2:]
	} else if strings.HasPrefix(arg, "-") {
		arg = arg[1:]
	} else {
		return "", false
	}
	if arg == "" {
		return "", false
	}
	return strings.ToLower(arg), true
}

// PowerShell accepts unambiguous prefixes for its command-line parameters.
// `-c`, `-Com`, and `-Comm` are the common short forms of -Command; the
// `com` prefix avoids mistaking -ConfigurationName for a command option.
func isPowerShellCommandFlag(arg string) bool {
	name, ok := powerShellOptionName(arg)
	return ok && (name == "c" || strings.HasPrefix(name, "com"))
}

func isPowerShellEncodedCommandFlag(arg string) bool {
	name, ok := powerShellOptionName(arg)
	return ok && (name == "e" || strings.HasPrefix(name, "enc"))
}

func isPowerShellFileFlag(arg string) bool {
	name, ok := powerShellOptionName(arg)
	return ok && (name == "f" || strings.HasPrefix(name, "fil"))
}

func stripCommandQuotes(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && ((s[0] == '(' && s[len(s)-1] == ')') ||
		(s[0] == '"' && s[len(s)-1] == '"') ||
		(s[0] == '\'' && s[len(s)-1] == '\'')) {
		if s[0] == '(' {
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		return stripQuotes(s)
	}
	return s
}

func classifyOpaqueCommand(part string) (Verdict, bool) {
	if opaqueBase64PipeRe != nil && matchOutsideQuotes(opaqueBase64PipeRe, part) {
		return opaqueVerdict("base64 -d | shell", "opaque-base64-pipe"), true
	}
	first := strings.ToLower(firstWord(strings.TrimSpace(part)))
	args := tokens(restAfterFirst(part))
	switch first {
	case "powershell", "pwsh":
		for _, arg := range args {
			if isPowerShellEncodedCommandFlag(arg) {
				return opaqueVerdict("EncodedCommand", "opaque-encoded-command"), true
			}
			if isPowerShellFileFlag(arg) {
				return opaqueVerdict("File", "opaque-file-command"), true
			}
		}
	case "python", "python3", "perl", "node", "nodejs", "ruby":
		for _, arg := range args {
			if strings.EqualFold(arg, "-c") || strings.EqualFold(arg, "-e") {
				return opaqueVerdict(first+" "+arg, "opaque-interpreter"), true
			}
		}
	case "awk":
		if strings.Contains(strings.ToLower(part), "system(") {
			return opaqueVerdict("awk system()", "opaque-awk-system"), true
		}
	}
	return Verdict{}, false
}

func opaqueVerdict(what, rule string) Verdict {
	return Verdict{
		Level:   Yellow,
		Rule:    rule,
		Reason:  what + " hides executable logic — the content cannot be safely checked by the text classifier",
		Matched: true,
	}
}

// ruleFn is a single rule: returns a verdict with Matched=true if
// the rule fires, else the zero Verdict (Matched=false) which the
// rule loop ignores. Keeping the call sites uniform costs a tiny
// amount of wrapping but makes adding a rule a one-line change.
type ruleFn func(part string) (Verdict, bool)

// tempSegments lists the directory names that make a path
// "obviously temporary" for the rm-recursive rule. The set is
// `node_modules`, `target`, `bin`, `obj`, `build`. System
// paths (`/usr/bin`, `/bin`) are deliberately excluded — see
// `isTempPath`.
var tempSegments = []string{"node_modules", "build", "target", "bin", "obj"}

// isTempPath reports whether `p` is "obviously temporary". `p` is
// the raw argument from the command line; quotes are stripped and
// doubled backslashes are collapsed before matching (an arg
// passed as "/tmp/build" or "\"C:\\Temp\\foo\"" or "C:\\Temp\\foo"
// must all yield the same answer). The match is on the
// lower-cased path. We don't resolve symlinks or evaluate env
// vars; the agent's command is what we read, not what the OS
// would do with it.
func isTempPath(p string) bool {
	if p == "" {
		return false
	}
	p = stripQuotes(p)
	p = multiBackslashRe.ReplaceAllString(p, `\`)
	lower := strings.ToLower(p)
	// System directories are never temp. A `rm -rf /usr/bin`
	// tagged "temp" would be a green false negative.
	if lower == "/usr" || strings.HasPrefix(lower, "/usr/") ||
		lower == "/bin" || strings.HasPrefix(lower, "/bin/") ||
		lower == "/sbin" || strings.HasPrefix(lower, "/sbin/") {
		return false
	}
	// Root and home are never temp — the rules explicitly carve
	// them out so `rm -rf /` and `rm -rf ~` stay Red.
	if lower == "/" || lower == "//" || lower == "/." ||
		lower == "~" || lower == "~/" || strings.HasPrefix(lower, "//") {
		return false
	}
	// Linux/Unix system temp.
	if strings.HasPrefix(lower, "/tmp/") || lower == "/tmp" {
		return true
	}
	if strings.HasPrefix(lower, "/var/tmp/") || lower == "/var/tmp" {
		return true
	}
	// Windows env-var form, verbatim in the command line.
	if strings.Contains(p, "$env:TEMP") || strings.Contains(p, "$env:TMP") ||
		strings.Contains(p, "%TEMP%") || strings.Contains(p, "%TMP%") {
		return true
	}
	// Windows temp dir verbatim.
	cands := []string{`c:\temp`, `c:/temp`}
	for _, c := range cands {
		if strings.HasPrefix(lower, c+`\`) || strings.HasPrefix(lower, c+`/`) || lower == c {
			return true
		}
	}
	// Temp path segments.
	for _, seg := range tempSegments {
		if pathHasSegment(lower, seg) {
			return true
		}
	}
	return false
}

// multiBackslashRe matches two-or-more adjacent backslashes —
// useful for collapsing doubled separators that PowerShell
// inside double-quoted paths produces, and for tolerating test
// inputs that double backslashes by accident.
var multiBackslashRe = regexp.MustCompile(`\\+`)

// pathHasSegment reports whether `seg` appears as a directory
// component in `lower` (a slash-normalized lower-case path). "bin"
// matches `proj/bin`, `/proj/bin`, `proj/bin/`, but not `cabin` and
// not `123-binary` — the segments are / or start/end of string.
func pathHasSegment(lower, seg string) bool {
	if lower == seg {
		return true
	}
	seps := []string{"/", "\\"}
	for _, s := range seps {
		prefix := seg + s
		if strings.HasPrefix(lower, prefix) {
			return true
		}
		both := s + seg + s
		if strings.Contains(lower, both) {
			return true
		}
		end := s + seg
		if strings.HasSuffix(lower, end) {
			return true
		}
	}
	return false
}

// stripQuotes strips matching outer quotes from s. Single quotes,
// double quotes, the backtick, and the typographic variants are all
// the same to a person copying a command line.
func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	const (
		leftDq  = "“"
		rightDq = "”"
		leftSq  = "‘"
		rightSq = "’"
	)
	for len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		switch {
		case first == '"' && last == '"',
			first == '\'' && last == '\'',
			first == '`' && last == '`':
			s = s[1 : len(s)-1]
		case strings.HasPrefix(s, leftDq) && strings.HasSuffix(s, rightDq):
			s = s[len(leftDq) : len(s)-len(rightDq)]
		case strings.HasPrefix(s, leftSq) && strings.HasSuffix(s, rightSq):
			s = s[len(leftSq) : len(s)-len(rightSq)]
		default:
			return s
		}
		s = strings.TrimSpace(s)
	}
	return s
}

// firstWord returns the first whitespace-separated token of `s`,
// with leading spaces removed. An empty input yields "". The token
// keeps its original case — rules that want case-insensitive
// matching lower-case the result themselves.
func firstWord(s string) string {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return ""
	}
	for i, r := range s {
		if unicode.IsSpace(r) {
			return s[:i]
		}
	}
	return s
}

// restAfterFirst returns everything in `s` after the first word,
// with leading whitespace trimmed. The result keeps its original
// case.
func restAfterFirst(s string) string {
	s = strings.TrimLeft(s, " \t")
	for i, r := range s {
		if unicode.IsSpace(r) {
			return strings.TrimLeft(s[i:], " \t")
		}
	}
	return ""
}

// tokens splits `s` on whitespace, with matched quotes collapsed so
// a quoted argument is one token. This is the same model most
// ad-hoc shell tokenizers use, and it's good enough for the rules:
// the design specifies no shell grammar, only that parsing is
// simple and textual.
func tokens(s string) []string {
	var out []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
				continue
			}
			cur.WriteByte(c)
		case '"':
			if !inSingle {
				inDouble = !inDouble
				continue
			}
			cur.WriteByte(c)
		case ' ', '\t':
			if !inSingle && !inDouble {
				flush()
				continue
			}
			cur.WriteByte(c)
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// lastArg returns the last token in `args`, with surrounding
// quotes stripped. `rm -rf /var/lib/postgresql` ⇒
// "/var/lib/postgresql".
func lastArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return stripQuotes(args[len(args)-1])
}

// hasRecurseFlag reports whether `args` carries any form of the
// recursive flag for either sh (`-r`, `-R`, `-rf`, `--recursive`)
// or PowerShell (`-Recurse`, `-r`). Combined short flags
// (`-rf`, `-FR`, `-fR`) are honoured.
func hasRecurseFlag(args []string) bool {
	for _, a := range args {
		if strings.EqualFold(a, "/s") {
			return true
		}
		if strings.HasPrefix(a, "-") {
			rest := strings.ToLower(strings.TrimLeft(a, "-"))
			if strings.HasPrefix(a, "--") {
				if rest == "recursive" {
					return true
				}
				continue
			}
			if rest == "" {
				continue
			}
			for _, r := range rest {
				if r == 'r' {
					return true
				}
			}
		}
	}
	return false
}

// hasForceFlag reports whether `args` carries any form of the
// force flag (`-f`, `--force`, combined forms like `-rf`).
func hasForceFlag(args []string) bool {
	for _, a := range args {
		if strings.EqualFold(a, "/q") {
			return true
		}
		if strings.HasPrefix(a, "-") {
			rest := strings.ToLower(strings.TrimLeft(a, "-"))
			if strings.HasPrefix(a, "--") {
				if rest == "force" {
					return true
				}
				continue
			}
			if rest == "" {
				continue
			}
			for _, r := range rest {
				if r == 'f' {
					return true
				}
			}
		}
	}
	return false
}

// isCriticalService reports whether `name` refers to one of the
// access points these rules single out: `sshd`, `ssh`, or anything
// starting with `iamtunnel`. PowerShell `DisplayName` strings
// ("OpenSSH SSH Server", "IAMTunnel Agent") carry the same signal,
// so substring matching for `ssh`/`sshd`/`iamtunnel` is included.
//
// Matching is case-insensitive. A trailing `.service` (systemd unit
// suffix) or `.exe` (process extension) is stripped first. The
// substring forms are deliberately broad: a service whose name
// happens to contain `ssh` as letters (e.g., an embedded name in a
// custom display string) is rare on a stock server, and the
// alternative — explicitly enumerating every conceivable display
// name — would re-create the "rule learned the wording" bug from
// FIX-1.
func isCriticalService(name string) bool {
	n := strings.ToLower(strings.TrimSpace(stripQuotes(name)))
	if n == "" {
		return false
	}
	n = strings.TrimSuffix(n, ".service")
	n = strings.TrimSuffix(n, ".exe")
	if n == "sshd" || n == "ssh" || n == "iamtunnel" {
		return true
	}
	if strings.HasPrefix(n, "iamtunnel-") || strings.HasPrefix(n, "iamtunnel_") {
		return true
	}
	// Substring forms — for DisplayName and similar human-readable
	// service identifiers.
	if strings.Contains(n, "sshd") || strings.Contains(n, "ssh") {
		return true
	}
	if strings.Contains(n, "iamtunnel") {
		return true
	}
	return false
}

// matchOutsideQuotes reports whether `re` finds any match in `s`
// that lies OUTSIDE of any quoted region (single quotes, double
// quotes, with backslash escape and PowerShell backtick escape).
// It is the textual analog of the note that grep -r "rm -rf"
// /home/deploy/scripts and echo "systemctl stop sshd" are handled
// correctly — so the "quoted content is not a command" mechanism
// already exists, but the SQL rule reads the raw string past it. Every
// rule that searches for keywords must be routed through that same
// mechanism, not only part of them.
//
// All rules that keyword-search the full part (sql-drop, fork bomb,
// redirect-to-block-device, dd-to-block-device, firewall reset,
// download-and-exec) go through this helper, so the keyword
// inside `git log --grep="drop table"` is not seen as a destructive
// operation while the same keyword inside `psql -c 'DROP TABLE'`
// is still seen (because psql is separately recognised as a SQL
// shell and its quoted argument is SQL data, not a pattern).
func matchOutsideQuotes(re *regexp.Regexp, s string) bool {
	locs := re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return false
	}
	for _, loc := range locs {
		matchStart := loc[0]
		if !insideQuotes(s, matchStart) {
			return true
		}
	}
	return false
}

// insideQuotes walks `s` up to (but not into) byte `pos` and reports
// whether `pos` lies inside a quoted region. Quote state tracks
// single quotes, double quotes, and PowerShell backtick escape;
// characters consumed by an escape are not re-counted as a quote.
func insideQuotes(s string, pos int) bool {
	inSingle, inDouble := false, false
	for i := 0; i < pos && i < len(s); i++ {
		c := s[i]
		if c == '\\' && !inSingle {
			i++ // skip next char
			continue
		}
		if c == '`' && !inSingle {
			i++ // skip next char
			continue
		}
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		}
	}
	return inSingle || inDouble
}

// ─────────────── Red rules ───────────────

// deleteOperationAliases is the single operation-to-spellings table used by
// both destructive and non-recursive deletion rules. Keeping aliases here
// prevents one spelling from quietly taking a different safety path.
var deleteOperationAliases = []struct {
	operation string
	names     []string
}{
	{operation: "rm", names: []string{"rm"}},
	{operation: "remove-item", names: []string{"ri", "Remove-Item", "del", "erase", "rmdir", "rd"}},
}

func deleteOperationFor(command string) (string, bool) {
	for _, operation := range deleteOperationAliases {
		for _, name := range operation.names {
			if strings.EqualFold(command, name) {
				return operation.operation, true
			}
		}
	}
	return "", false
}

// redRules is checked before yellow ones because some of them
// override what would otherwise be a yellow match (ssh service
// stop, removing an exe from disk).
var redRules = []ruleFn{
	ruleRMDangerous,
	ruleRemoveItemDangerous,
	ruleDiskFormat,
	ruleDDToBlockDev,
	ruleRedirectToBlockDev,
	ruleForkBomb,
	ruleFirewallReset,
	ruleCriticalServiceAction,
	ruleUserDelete,
	ruleSQLDestruction,
	ruleShutdownOrReboot,
	ruleWipeFreeSpace,
	ruleChmodRoot,
	ruleChownRoot,
}

// ── rm-recursive-outside-temp / -inside-temp / -root ──

func ruleRMDangerous(part string) (Verdict, bool) {
	cmd := firstWord(part)
	operation, ok := deleteOperationFor(cmd)
	if !ok || operation != "rm" {
		return Verdict{}, false
	}
	args := tokens(restAfterFirst(part))
	if !hasRecurseFlag(args) || !hasForceFlag(args) {
		// No-recurse → yellow rule; just -r (no -f) outside temp
		// is not covered by any rule, so unmatched.
		return Verdict{}, false
	}
	return classifyRecursiveDeletePaths(args, "rm")
}

// ── Remove-Item -Recurse -Force ──

func ruleRemoveItemDangerous(part string) (Verdict, bool) {
	cmd := firstWord(part)
	operation, ok := deleteOperationFor(cmd)
	if !ok || operation != "remove-item" {
		return Verdict{}, false
	}
	args := tokens(restAfterFirst(part))
	if !hasRecurseFlag(args) || !hasForceFlag(args) {
		return Verdict{}, false
	}
	return classifyRecursiveDeletePaths(args, "remove-item")
}

// classifyRecursiveDeletePaths examines every non-flag argument. A command
// with several paths is as dangerous as its most dangerous path; returning
// after the first path would let a harmless temporary path hide a later red
// target.
func classifyRecursiveDeletePaths(args []string, operation string) (Verdict, bool) {
	var worst Verdict
	for _, a := range args {
		if strings.HasPrefix(a, "-") || strings.EqualFold(a, "/s") || strings.EqualFold(a, "/q") {
			continue
		}
		path := stripQuotes(a)
		var candidate Verdict
		switch {
		case operation == "rm" && (path == "/" || path == "//" || path == "/." ||
			path == "~" || path == "~/" || strings.HasPrefix(path, "//")):
			candidate = Verdict{
				Level:   Red,
				Rule:    "rm-recursive-root",
				Reason:  "rm -rf at filesystem root '" + path + "' destroys all disk contents with no way to recover them",
				Matched: true,
			}
		case !isTempPath(path):
			reason := "recursive forced deletion of '" + path + "' outside temporary directories — data will be lost"
			if operation == "remove-item" {
				reason = "Remove-Item -Recurse -Force outside temporary directories ('" + path + "') — data will be lost"
			}
			candidate = Verdict{
				Level:   Red,
				Rule:    operation + "-recursive-outside-temp",
				Reason:  reason,
				Matched: true,
			}
		default:
			reason := "recursive deletion in an obviously temporary directory '" + path + "' — reversible"
			if operation == "remove-item" {
				reason = "Remove-Item in an obviously temporary directory '" + path + "' — reversible"
			}
			candidate = Verdict{
				Level:   Green,
				Rule:    operation + "-recursive-inside-temp",
				Reason:  reason,
				Matched: true,
			}
		}
		if worseThan(candidate, worst) {
			worst = candidate
		}
	}
	if !worst.Matched {
		return Verdict{}, false
	}
	return worst, true
}

// ── disk formatting ──

func ruleDiskFormat(part string) (Verdict, bool) {
	lower := strings.ToLower(firstWord(part))
	switch lower {
	case "mkfs":
		return Verdict{
			Level:   Red,
			Rule:    "disk-format",
			Reason:  "mkfs formats the filesystem on the device — all data will be erased",
			Matched: true,
		}, true
	case "fdisk", "diskpart":
		return Verdict{
			Level:   Red,
			Rule:    "disk-partition",
			Reason:  lower + " changes the disk partition table with no rollback without a backup",
			Matched: true,
		}, true
	case "format":
		// Match literal "format" only — `Format-Table`,
		// `Format-List`, `Format-Custom` all keep the hyphen and
		// aren't picked up here.
		return Verdict{
			Level:   Red,
			Rule:    "format-volume",
			Reason:  "format erases and repartitions the volume — data on it will be lost",
			Matched: true,
		}, true
	}
	if strings.HasPrefix(lower, "mkfs.") || strings.HasPrefix(lower, "mkfs_") {
		return Verdict{
			Level:   Red,
			Rule:    "disk-format",
			Reason:  lower + " formats the filesystem — data on the device will be lost",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── dd of=/dev/... ──

// blockDevRe matches `of=/dev/<device>` where <device> is one of
// the well-known block-device prefixes (`sd`, `nvme`, `hd`, `vd`,
// `xvd`) followed by alphanumerics. We don't try to enumerate the
// kernel partition-number grammar exactly — `nvme0n1p2`, `sda1`,
// `vda` all match the same shape.
var blockDevRe = regexp.MustCompile(`(?i)\bof=/dev/(?:sd[a-z0-9]+|nvme[0-9]+n[0-9]+(?:p[0-9]+)?|hd[a-z0-9]+|vd[a-z0-9]+|xvd[a-z0-9]+)\b`)

func ruleDDToBlockDev(part string) (Verdict, bool) {
	if !strings.EqualFold(firstWord(part), "dd") {
		return Verdict{}, false
	}
	if matchOutsideQuotes(blockDevRe, part) {
		return Verdict{
			Level:   Red,
			Rule:    "dd-block-device",
			Reason:  "dd writes directly to a block device — it can destroy the partition table or an existing filesystem",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── > /dev/sd*, > /dev/nvme* ──

var redirectBlockDevRe = regexp.MustCompile(`(?i)(?:>\s?|>>\s?|2>\s?|&\s?>?\s?)/dev/(?:sd[a-z0-9]+|nvme[0-9]+n[0-9]+(?:p[0-9]+)?|hd[a-z0-9]+|vd[a-z0-9]+|xvd[a-z0-9]+)\b`)

func ruleRedirectToBlockDev(part string) (Verdict, bool) {
	if matchOutsideQuotes(redirectBlockDevRe, part) {
		return Verdict{
			Level:   Red,
			Rule:    "redirect-block-device",
			Reason:  "redirecting output to a block device — erases the contents of a partition or disk",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── fork bomb ──

// forkBombRe matches the canonical bash fork bomb in any
// reasonable spacing variation: `:(){ … };:`. We require a
// function name `:` with the empty-arg `()`, an opening `{`, a
// body containing one `|` (the recursive call piped to the
// next) and one `&` (background), and a closing `}`. The
// trailing `;:` invocation is optional, because the splitter
// cuts on `;` and may separate the body and the invocation
// into two parts; the rule must catch either form.
var forkBombRe = regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:[^{}]*\|[^{}]*&[^{}]*\}(?:\s*;\s*:?)?`)

func ruleForkBomb(part string) (Verdict, bool) {
	if matchOutsideQuotes(forkBombRe, part) {
		return Verdict{
			Level:   Red,
			Rule:    "fork-bomb",
			Reason:  "fork bomb — exhausts the process table and can hang the machine until reboot",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── iptables -F/-X, netsh advfirewall reset ──

func ruleFirewallReset(part string) (Verdict, bool) {
	flushRe := regexp.MustCompile(`\biptables\s+-[fFxX]\b`)
	if matchOutsideQuotes(flushRe, part) {
		return Verdict{
			Level:   Red,
			Rule:    "iptables-flush",
			Reason:  "iptables -F/-X flushes all firewall rules with no way to restore them",
			Matched: true,
		}, true
	}
	flushWordRe := regexp.MustCompile(`\biptables\s+--flush\b`)
	if matchOutsideQuotes(flushWordRe, part) {
		return Verdict{
			Level:   Red,
			Rule:    "iptables-flush",
			Reason:  "iptables --flush flushes all firewall rules",
			Matched: true,
		}, true
	}
	resetRe := regexp.MustCompile(`\bnetsh\s+advfirewall\s+reset\b`)
	if matchOutsideQuotes(resetRe, part) {
		return Verdict{
			Level:   Red,
			Rule:    "netsh-advfirewall-reset",
			Reason:  "netsh advfirewall reset resets Windows Firewall to factory settings",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── stopping / killing sshd, ssh, anything iamtunnel* ──

// extractNamedTarget walks `args` looking for a target name in any
// of the recognized shapes:
//
//   - Positional: `Stop-Service sshd` — `args[0]` is the service
//     name (when `args[0]` doesn't start with `-`).
//   - Separate flag: `Stop-Service -Name sshd -Force` — `-Name`
//     takes the next token as the value.
//   - Colon form: `Stop-Service -Name:sshd` — the value is on the
//     same token after the colon.
//   - Equals form: `Stop-Service -Name=sshd` — handled too.
//
// The same reader covers process names (`Stop-Process -Name ssh`,
// `taskkill /IM ssh.exe`, `Stop-Process -Id 1234`). The recognized
// parameter names are listed in `namedTargetFlags` below.
//
// Returns "" when no recognizable target is present (e.g. `pkill`
// with no argument, or a positional-only call with no positional
// arg). The caller treats an empty target as "no service-name
// identifier found" — which the Red rule then turns into
// Yellow via the general service-action rule.
func extractNamedTarget(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		lower := strings.ToLower(a)
		// Colon form: `-Name:sshd`, `-Name:sshd.exe`.
		for _, name := range namedTargetFlags {
			prefix := name + ":"
			if strings.HasPrefix(lower, prefix) {
				return stripQuotes(a[len(prefix):])
			}
		}
		// Equals form is already in the same token; covered by the
		// `-Name value` branch below (value lives in the next token,
		// which `-Name=foo` does not have).
		switch lower {
		case "-name", "-displayname", "-inputobject", "-servicename", "-id":
			if i+1 < len(args) {
				return stripQuotes(args[i+1])
			}
			return ""
		}
		// Positional target: a token that is not a flag and not part
		// of a recognized pair. The first such token wins.
		if a == "" || strings.HasPrefix(a, "-") || strings.HasPrefix(a, "/") {
			continue
		}
		return stripQuotes(a)
	}
	return ""
}

// namedTargetFlags is the closed set of PowerShell parameter names
// that carry the service or process target. Adding a parameter to
// this list without also teaching a test for it is exactly the
// shape of bug FIX-1 calls out — the rules learn the wording, not
// the action. Tests must cover each name; non-listed parameter
// names are deliberately ignored to avoid binding to parameter
// shapes we have not vetted.
var namedTargetFlags = []string{
	"-name", "-displayname", "-inputobject", "-servicename", "-id",
}

// serviceMgmtVerbs is the closed set of verbs that turn a
// service-management call into a stop / disable / restart / etc.
// action. Anything not in this list is a sub-command whose name
// tells us nothing about destructive intent (`systemctl status`
// or `systemctl list-units` need no Yellow flag).
var serviceMgmtVerbs = map[string]bool{
	"stop":    true,
	"kill":    true,
	"disable": true,
	"mask":    true,
	"start":   true,
	"restart": true,
	"delete":  true,
}

// scVerbs is the closed set of `sc.exe` verbs that change state.
// `sc.exe config` modifies startup type without stopping — that
// is a yellow-level action and gets its own verb here.
var scVerbs = map[string]bool{
	"stop":   true,
	"delete": true,
	"config": true,
}

// firstServiceMgmtVerb returns the first argument in `args` that
// (a) is not a flag, (b) matches one of the recognized
// service-management verbs, and the rest of the args past it. So
// `systemctl --no-pager --quiet disable --now sshd` finds
// `disable` and returns ("disable", ["--now", "sshd"], true).
//
// When no verb is found, the returned `verb` is "" and `argsAfter`
// is nil — the caller treats that as "not a service-management
// action".
func firstServiceMgmtVerb(args []string, verbs map[string]bool) (verb string, argsAfter []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "/") {
			continue
		}
		if verbs[a] {
			return a, args[i+1:]
		}
		// First non-flag was a noun, not a verb — there is no
		// service-management action here (e.g. `systemctl status`).
		return "", nil
	}
	return "", nil
}

// serviceOperationAliases is the operation-to-spellings table for service
// cmdlets. PowerShell's `spsv` is Stop-Service; keeping it beside the long
// spelling prevents the alias from taking a different safety path.
var serviceOperationAliases = []struct {
	operation string
	names     []string
}{
	{operation: "stop", names: []string{"stop-service", "spsv"}},
	{operation: "restart", names: []string{"restart-service"}},
}

func serviceOperationFor(command string) (string, bool) {
	for _, operation := range serviceOperationAliases {
		for _, name := range operation.names {
			if command == name {
				return operation.operation, true
			}
		}
	}
	return "", false
}

// detectServiceManagementAction returns (verb, target, true) for any
// of: `systemctl [verb] NAME`, `service NAME verb`,
// `Stop-Service NAME`, `spsv NAME`, `Restart-Service NAME`,
// `sc.exe [verb] NAME`, `net stop NAME`.
//
// The verb is one of the recognized service-management verbs:
// "stop", "disable", "delete", "restart", "start", "mask", "kill",
// "config". Global flags are tolerated before both the verb
// (`systemctl --no-pager disable sshd`) and the target
// (`systemctl disable --now sshd`).
func detectServiceManagementAction(part string) (verb, target string, ok bool) {
	cmd := strings.ToLower(firstWord(part))
	args := tokens(strings.ToLower(restAfterFirst(part)))
	switch cmd {
	case "systemctl":
		v, rest := firstServiceMgmtVerb(args, serviceMgmtVerbs)
		if v != "" {
			return v, extractNamedTarget(rest), true
		}
	case "service":
		// service NAME [verb] — name is positional, verb follows.
		// Global flags before NAME are not standard for the
		// SysV `service` utility, so we only handle the bare case.
		if len(args) >= 2 {
			if serviceMgmtVerbs[args[1]] {
				return args[1], stripQuotes(args[0]), true
			}
		}
	case "stop-service", "spsv", "restart-service":
		v, _ := serviceOperationFor(cmd)
		target := extractNamedTarget(args)
		return v, target, true
	case "sc", "sc.exe":
		v, rest := firstServiceMgmtVerb(args, scVerbs)
		if v != "" {
			return v, extractNamedTarget(rest), true
		}
	case "net":
		v, rest := firstServiceMgmtVerb(args, map[string]bool{"stop": true})
		if v != "" {
			return v, extractNamedTarget(rest), true
		}
	}
	return "", "", false
}

// detectProcessKillAction returns (verb, target, true) for any of:
// `pkill NAME`, `killall NAME`, `kill [flags...] NAME|PID`,
// `taskkill /IM NAME`, `Stop-Process -Name NAME`. The target is
// the process name when known, the PID as a string when not;
// an empty target is possible (e.g. `pkill` with no name). The
// verb is the canonical verb (`kill`); for `kill -9` etc. the
// flag check happens in the rule, not here.
//
// The recognised process-name callers trim a trailing `.exe` from
// the target so `taskkill /IM sshd.exe` and `Stop-Process -Name
// sshd.exe` both surface `sshd` and reach the same critical-service
// check as `pkill sshd`.
func detectProcessKillAction(part string) (verb, target string, ok bool) {
	cmd := strings.ToLower(firstWord(part))
	args := tokens(strings.ToLower(restAfterFirst(part)))
	switch cmd {
	case "pkill", "killall", "kill":
		target = extractNamedTarget(args)
		return "kill", target, true
	case "taskkill", "stop-process":
		target := extractNamedTarget(args)
		return "kill", strings.TrimSuffix(target, ".exe"), true
	}
	return "", "", false
}

// isKillFlag covers `kill`'s many "definitely kill" forms: -9 /
// -KILL / -SIGKILL are the same intent — drop a process now. -15 /
// -TERM / -SIGTERM are "polite" kills; we still flag them as
// yellow because terminating a process is an action with side
// effects (`kill -9` is the smallest
// unconditional form, but a terminate is similarly irreversible in
// the moment).
func isKillFlag(a string) bool {
	switch a {
	case "-9", "-kill", "-sigkill", "-15", "-term", "-sigterm", "-s9", "-sk", "-sk9":
		return true
	}
	return false
}

// redServiceKillVerbs is the closed set of verbs that turn a
// service-management or process-kill action into a Red verdict
// when the target is critical.
var redServiceKillVerbs = map[string]bool{
	"stop":    true,
	"disable": true,
	"delete":  true,
	"kill":    true,
	"mask":    true,
}

// yellowServiceMgmtVerbs are the verbs that warrant Yellow for
// non-critical services. "config" turns an `sc.exe config` into a
// recognition; "kill" on a non-ssh process is yellow per the
// rules on killing processes.
var yellowServiceMgmtVerbs = map[string]bool{
	"stop": true, "disable": true, "restart": true,
	"config": true, "kill": true,
}

func ruleCriticalServiceAction(part string) (Verdict, bool) {
	// Service-management form: `systemctl stop sshd`,
	// `Stop-Service sshd`, `sc.exe delete sshd`, `net stop sshd`.
	if verb, target, ok := detectServiceManagementAction(part); ok {
		if redServiceKillVerbs[verb] && isCriticalService(target) {
			return Verdict{
				Level:   Red,
				Rule:    "ssh-or-tunnel-service-action",
				Reason:  "command '" + verb + " " + target + "' cuts off the owner's access to this machine — there will be no way to repair it remotely",
				Matched: true,
			}, true
		}
	}
	// Process-kill form: `pkill sshd`, `kill -9 sshd`, `Stop-Process -Name sshd`.
	if verb, target, ok := detectProcessKillAction(part); ok {
		if verb == "kill" && isCriticalService(target) {
			return Verdict{
				Level:   Red,
				Rule:    "ssh-or-tunnel-service-action",
				Reason:  "killing process '" + target + "' cuts off the owner's access to this machine — there will be no way to repair it remotely",
				Matched: true,
			}, true
		}
	}
	return Verdict{}, false
}

// ── user deletion ──

func ruleUserDelete(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	switch cmd {
	case "userdel", "deluser":
		return Verdict{
			Level:   Red,
			Rule:    "user-delete",
			Reason:  "userdel/deluser deletes a user account — access to the account and its profile data will be lost",
			Matched: true,
		}, true
	case "remove-localuser":
		return Verdict{
			Level:   Red,
			Rule:    "user-delete",
			Reason:  "Remove-LocalUser deletes a Windows account — it cannot be recovered without a backup",
			Matched: true,
		}, true
	}
	args := tokens(strings.ToLower(part))
	if len(args) >= 3 && args[0] == "net" && args[1] == "user" {
		// `net user <name> /delete` — the last token may be /DELETE.
		for _, a := range args[2:] {
			if a == "/delete" || a == "/del" {
				return Verdict{
					Level:   Red,
					Rule:    "user-delete",
					Reason:  "net user … /delete deletes a Windows user account",
					Matched: true,
				}, true
			}
		}
	}
	return Verdict{}, false
}

// ── SQL DROP / TRUNCATE ──

var sqlDestructiveRe = regexp.MustCompile(`(?i)\b(?:drop\s+(?:database|schema|table|index|view)|truncate\s+(?:table\s+)?[^\s;]+)\b`)

// sqlShellCommands lists the first-words of commands whose entire
// job is to execute a SQL string. Their quoted arguments are SQL
// data — not patterns and not shell escapes — so the SQL
// destruction rule fires for them even when the keyword itself
// sits inside quotes (`mysql -e "DROP TABLE foo"`).
//
// The list is intentionally narrow. A `mysql`-like binary not on
// this list has to slip the keyword outside its quotes for the
// rule to fire.
var sqlShellCommands = map[string]bool{
	"psql":     true,
	"mysql":    true,
	"mariadb":  true,
	"sqlcmd":   true,
	"sqlite3":  true,
	"sqlite":   true,
	"sqlplus":  true,
	"isql":     true,
	"db2":      true,
	"redshift": true,
	"snowsql":  true,
}

func ruleSQLDestruction(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	if sqlShellCommands[cmd] {
		// The whole point of the shell is to execute the quoted
		// SQL string — match the keyword anywhere on the line.
		if sqlDestructiveRe.MatchString(part) {
			return Verdict{
				Level:   Red,
				Rule:    "sql-drop-truncate",
				Reason:  "SQL DROP/TRUNCATE is executed through " + cmd + " — rollback is possible only from a backup",
				Matched: true,
			}, true
		}
	}
	// General command: the keyword must appear OUTSIDE of quotes
	// to count as a real SQL operation. Otherwise, `git log
	// --grep="drop table"` becomes Red, which it isn't — it's a
	// history grep, not a database operation.
	if matchOutsideQuotes(sqlDestructiveRe, part) {
		return Verdict{
			Level:   Red,
			Rule:    "sql-drop-truncate",
			Reason:  "SQL DROP/TRUNCATE — rollback is possible only from a backup",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── shutdown, reboot, halt, poweroff ──

func ruleShutdownOrReboot(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	switch cmd {
	case "shutdown", "reboot", "halt", "poweroff":
		return Verdict{
			Level:   Red,
			Rule:    "shutdown-reboot",
			Reason:  cmd + " shuts down or reboots the machine — the current SSH session will be interrupted",
			Matched: true,
		}, true
	case "init":
		// `init 0`, `init 6` shut down / reboot too, but only with
		// those specific runlevels.
		args := tokens(restAfterFirst(part))
		if len(args) == 0 || (args[0] != "0" && args[0] != "6") {
			return Verdict{}, false
		}
		return Verdict{
			Level:   Red,
			Rule:    "shutdown-reboot",
			Reason:  "init " + args[0] + " shuts down or reboots the machine",
			Matched: true,
		}, true
	case "restart-computer", "stop-computer":
		return Verdict{
			Level:   Red,
			Rule:    "shutdown-reboot",
			Reason:  cmd + " shuts down or reboots the machine — the current session will be interrupted",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── cipher /w, sdelete ──

func ruleWipeFreeSpace(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	switch cmd {
	case "sdelete":
		return Verdict{
			Level:   Red,
			Rule:    "sdelete-wipe",
			Reason:  "sdelete overwrites file contents and/or free space — the data cannot be recovered",
			Matched: true,
		}, true
	case "cipher":
		args := tokens(strings.ToLower(part))
		for _, a := range args[1:] {
			if a == "/w" || a == "-w" {
				return Verdict{
					Level:   Red,
					Rule:    "cipher-wipe",
					Reason:  "cipher /w overwrites free space on the specified volume — it removes traces in bulk",
					Matched: true,
				}, true
			}
		}
	}
	return Verdict{}, false
}

// ── chmod -R 777 / , chown -R <user> / ──

func ruleChmodRoot(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	if cmd != "chmod" {
		return Verdict{}, false
	}
	args := tokens(restAfterFirst(part))
	if !hasRecurseFlag(args) {
		return Verdict{}, false
	}
	if !isSystemRootPath(lastArg(args)) {
		return Verdict{}, false
	}
	return Verdict{
		Level:   Red,
		Rule:    "chmod-recursive-root",
		Reason:  "chmod -R on '/' changes permissions across the system — it may make the system unusable",
		Matched: true,
	}, true
}

func ruleChownRoot(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	if cmd != "chown" {
		return Verdict{}, false
	}
	args := tokens(restAfterFirst(part))
	if !hasRecurseFlag(args) {
		return Verdict{}, false
	}
	if !isSystemRootPath(lastArg(args)) {
		return Verdict{}, false
	}
	return Verdict{
		Level:   Red,
		Rule:    "chown-recursive-root",
		Reason:  "chown -R on '/' rewrites ownership of every file on the system",
		Matched: true,
	}, true
}

// ─────────────── Yellow rules ───────────────

var yellowRules = []ruleFn{
	ruleRmNonRecursive,
	ruleProcessKill,
	ruleServiceActionOther,
	ruleRegistryHKLM,
	ruleNetworkSettings,
	ruleAccountManagement,
	ruleSetExecutionPolicy,
	ruleScheduler,
	ruleGitDestructive,
	ruleDownloadExec,
	ruleInstallOrElevate,
	ruleSystemDirWrite,
}

// ── rm / del / Remove-Item without recursion ──

func ruleRmNonRecursive(part string) (Verdict, bool) {
	cmd := firstWord(part)
	if _, ok := deleteOperationFor(cmd); !ok {
		return Verdict{}, false
	}
	args := tokens(restAfterFirst(part))
	if hasRecurseFlag(args) {
		// Recursion is handled by ruleRMDangerous /
		// ruleRemoveItemDangerous.
		return Verdict{}, false
	}
	return Verdict{
		Level:   Yellow,
		Rule:    "rm-non-recursive",
		Reason:  "rm/del/Remove-Item deletes a file or directory — it can only be undone from a backup",
		Matched: true,
	}, true
}

// ── process kill (non-ssh targets): taskkill /IM, pkill, kill -9, Stop-Process ──

func ruleProcessKill(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	switch cmd {
	case "taskkill", "pkill", "killall", "stop-process":
		_, target, _ := detectProcessKillAction(part)
		if isCriticalService(target) {
			// Red ssh rule already matched.
			return Verdict{}, false
		}
		return Verdict{
			Level:   Yellow,
			Rule:    "process-kill",
			Reason:  cmd + describeProcessTarget(target),
			Matched: true,
		}, true
	case "kill":
		args := tokens(part)
		hasKill := false
		for _, a := range args {
			if isKillFlag(strings.ToLower(a)) {
				hasKill = true
				break
			}
		}
		if !hasKill {
			return Verdict{}, false
		}
		_, target, _ := detectProcessKillAction(part)
		if isCriticalService(target) {
			return Verdict{}, false
		}
		return Verdict{
			Level:   Yellow,
			Rule:    "process-kill",
			Reason:  "kill process" + describeProcessTarget(target),
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// describeProcessTarget renders a target name into a
// human-readable fragment (` nginx`) for use in the Reason string.
// Empty input yields an empty fragment.
func describeProcessTarget(target string) string {
	t := strings.TrimSpace(stripQuotes(target))
	if t == "" {
		return ""
	}
	return " '" + t + "'"
}

// ── service-management actions (other targets and other verbs): Stop-Service, sc.exe config, etc ──

func ruleServiceActionOther(part string) (Verdict, bool) {
	verb, target, ok := detectServiceManagementAction(part)
	if !ok {
		return Verdict{}, false
	}
	if !yellowServiceMgmtVerbs[verb] {
		return Verdict{}, false
	}
	if isCriticalService(target) && redServiceKillVerbs[verb] {
		// Red ssh rule already matched.
		return Verdict{}, false
	}
	what := "service"
	if target != "" {
		what = "service '" + target + "'"
	}
	if verb == "kill" {
		// `sc.exe` doesn't have a kill verb; this branch catches
		// service-stop verbs only.
		what = "service '" + target + "'"
	}
	return Verdict{
		Level:   Yellow,
		Rule:    "service-action-other",
		Reason:  "command '" + verb + " " + what + "' — other processes may lose a dependency",
		Matched: true,
	}, true
}

// ── reg add|delete HKLM, Set-ItemProperty, New-ItemProperty ──

func ruleRegistryHKLM(part string) (Verdict, bool) {
	lower := strings.ToLower(part)
	cmd := strings.ToLower(firstWord(part))
	if cmd == "reg" {
		args := tokens(lower)
		for i, a := range args {
			if a == "add" || a == "delete" {
				if i+1 < len(args) {
					next := strings.ToLower(args[i+1])
					if strings.HasPrefix(next, "hklm") || strings.HasPrefix(next, "hkey_local_machine") {
						return Verdict{
							Level:   Yellow,
							Rule:    "registry-machinelocal-write",
							Reason:  "reg " + a + " on HKLM — changes the machine registry hive and affects all users",
							Matched: true,
						}, true
					}
				}
			}
		}
		return Verdict{}, false
	}
	if cmd == "set-itemproperty" || cmd == "new-itemproperty" || cmd == "remove-itemproperty" {
		if strings.Contains(lower, "hklm") || strings.Contains(lower, "hkey_local_machine") {
			return Verdict{
				Level:   Yellow,
				Rule:    "registry-machinelocal-write",
				Reason:  cmd + " on the HKLM branch — changes the Windows machine registry",
				Matched: true,
			}, true
		}
	}
	return Verdict{}, false
}

// ── netsh (except advfirewall reset), New-NetFirewallRule, Set-NetFirewallProfile, route add/delete ──

func ruleNetworkSettings(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	lower := strings.ToLower(part)
	switch cmd {
	case "netsh":
		if regexp.MustCompile(`\badvfirewall\s+reset\b`).MatchString(lower) {
			// Red rule already.
			return Verdict{}, false
		}
		return Verdict{
			Level:   Yellow,
			Rule:    "netsh-network-setting",
			Reason:  "netsh changes Windows network settings — it may break networking until reboot",
			Matched: true,
		}, true
	case "new-netfirewallrule", "set-netfirewallprofile", "remove-netfirewallrule":
		return Verdict{
			Level:   Yellow,
			Rule:    "powershell-firewall",
			Reason:  cmd + " changes Windows Firewall rules",
			Matched: true,
		}, true
	case "route":
		args := tokens(lower)
		if len(args) >= 2 && (args[1] == "add" || args[1] == "delete" || args[1] == "change") {
			return Verdict{
				Level:   Yellow,
				Rule:    "route-table",
				Reason:  "route add/delete/change changes the routing table — it may cut off the network",
				Matched: true,
			}, true
		}
	}
	return Verdict{}, false
}

// ── New-LocalUser, Add-LocalGroupMember, net user, net localgroup, useradd, usermod ──

func ruleAccountManagement(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	lower := strings.ToLower(part)
	args := tokens(lower)
	switch cmd {
	case "new-localuser", "set-localuser", "add-localgroupmember",
		"remove-localgroupmember", "add-localgroup", "new-localgroup":
		return Verdict{
			Level:   Yellow,
			Rule:    "account-management",
			Reason:  cmd + " changes the membership of local Windows accounts or groups",
			Matched: true,
		}, true
	case "useradd", "usermod", "groupadd", "groupmod", "passwd":
		return Verdict{
			Level:   Yellow,
			Rule:    "account-management",
			Reason:  cmd + " changes a Linux user account or group",
			Matched: true,
		}, true
	case "userdel", "deluser", "remove-localuser":
		// RED rule handled this; do not re-fire here.
		return Verdict{}, false
	case "net":
		if len(args) >= 2 {
			switch args[1] {
			case "user", "localgroup", "group":
				for _, a := range args[2:] {
					if a == "/delete" || a == "/del" {
						return Verdict{}, false
					}
				}
				return Verdict{
					Level:   Yellow,
					Rule:    "account-management",
					Reason:  "net " + args[1] + " — changes Windows user accounts or groups",
					Matched: true,
				}, true
			}
		}
	}
	return Verdict{}, false
}

// ── Set-ExecutionPolicy ──

func ruleSetExecutionPolicy(part string) (Verdict, bool) {
	if strings.EqualFold(firstWord(part), "Set-ExecutionPolicy") {
		return Verdict{
			Level:   Yellow,
			Rule:    "set-executionpolicy",
			Reason:  "Set-ExecutionPolicy changes the PowerShell script execution policy",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── schtasks /create|/delete|/change, Register-ScheduledTask, Unregister-ScheduledTask, crontab ──

func ruleScheduler(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	switch cmd {
	case "schtasks":
		args := tokens(strings.ToLower(part))
		for _, a := range args[1:] {
			if a == "/create" || a == "/delete" || a == "/change" ||
				a == "-create" || a == "-delete" || a == "-change" {
				return Verdict{
					Level:   Yellow,
					Rule:    "scheduler-write",
					Reason:  "schtasks " + a + " changes the Windows scheduled-task schedule",
					Matched: true,
				}, true
			}
		}
	case "register-scheduledtask", "unregister-scheduledtask", "set-scheduledtask":
		return Verdict{
			Level:   Yellow,
			Rule:    "scheduler-write",
			Reason:  cmd + " changes the Windows scheduled-task schedule",
			Matched: true,
		}, true
	case "crontab":
		return Verdict{
			Level:   Yellow,
			Rule:    "crontab-write",
			Reason:  "crontab changes the Linux task schedule",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ── git push --force, git reset --hard, git clean -fd ──

func ruleGitDestructive(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	if cmd != "git" {
		return Verdict{}, false
	}
	args := tokens(strings.ToLower(part))
	if len(args) < 3 {
		return Verdict{}, false
	}
	sub := args[1]
	switch sub {
	case "push":
		for _, a := range args[2:] {
			if a == "--force" || a == "-force" || a == "-f" ||
				strings.HasPrefix(a, "--force-with-lease") {
				return Verdict{
					Level:   Yellow,
					Rule:    "git-push-force",
					Reason:  "git push --force/-f overwrites remote history — someone else's work may be lost",
					Matched: true,
				}, true
			}
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
				rest := a[1:]
				if strings.Contains(rest, "f") {
					return Verdict{
						Level:   Yellow,
						Rule:    "git-push-force",
						Reason:  "git push with the -f flag overwrites remote history",
						Matched: true,
					}, true
				}
			}
		}
	case "reset":
		for _, a := range args[2:] {
			if a == "--hard" || a == "-hard" {
				return Verdict{
					Level:   Yellow,
					Rule:    "git-reset-hard",
					Reason:  "git reset --hard discards uncommitted working-tree changes",
					Matched: true,
				}, true
			}
		}
	case "clean":
		for _, a := range args[2:] {
			if !strings.HasPrefix(a, "-") {
				continue
			}
			rest := strings.ToLower(strings.TrimLeft(a, "-"))
			if strings.Contains(rest, "f") {
				return Verdict{
					Level:   Yellow,
					Rule:    "git-clean",
					Reason:  "git clean deletes untracked files — recovery is possible only from reflog or filesystem undelete",
					Matched: true,
				}, true
			}
		}
	}
	return Verdict{}, false
}

// ── curl … | sh , Invoke-Expression ──

// matchPipeToExec matches whole-command pipelines that span a `|`.
// Returns true for `curl … | sh`, `iwr … | iex`,
// `Invoke-Expression …`. The split on `|` would hide these as
// "curl" on one side and "sh" on the other — exactly the attack
// pattern the rule exists to catch.
func matchPipeToExec(command string) (Verdict, bool) {
	lower := strings.ToLower(command)
	re := regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:(?:sudo|doas|runas)\b[^\n|]*?\s+)?(?:sh|bash|zsh|ksh|dash|ash|pdksh)\b`)
	if matchOutsideQuotes(re, command) {
		return Verdict{
			Level:   Yellow,
			Rule:    "download-and-exec",
			Reason:  "downloading with curl/wget and immediately executing in sh/bash without checking the content",
			Matched: true,
		}, true
	}
	re = regexp.MustCompile(`(?i)\b(?:invoke-webrequest|iwr|curl|wget)\b[^\n|]*\|\s*(?:(?:sudo|doas|runas)\b[^\n|]*?\s+)?(?:iex|invoke-expression)\b`)
	if matchOutsideQuotes(re, command) {
		return Verdict{
			Level:   Yellow,
			Rule:    "download-and-exec-powershell",
			Reason:  "Invoke-WebRequest/curl piped to Invoke-Expression/iex — without checking the content",
			Matched: true,
		}, true
	}
	// Invoke-Expression standing alone has no inner quoted region
	// to worry about; the prefix check below is enough.
	if strings.HasPrefix(lower, "invoke-expression ") || lower == "invoke-expression" {
		return Verdict{
			Level:   Yellow,
			Rule:    "invoke-expression",
			Reason:  "Invoke-Expression executes a string as PowerShell code — dangerous even without a pipe",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// ruleDownloadExec is also run per-part so that a single segment
// (rare, but reachable if the splitter is bypassed) still gets the
// right verdict.
func ruleDownloadExec(part string) (Verdict, bool) {
	return matchPipeToExec(part)
}

// ── sudo / doas / runas ──

// elevatorCommandNames is the list of first-words that identify a
// privilege-elevator prefix. Anything in this list is removed
// before the rest is classified, so a destructive command
// executed via `sudo …` returns the same verdict as the
// destructive command itself.
var elevatorCommandNames = map[string]bool{
	"sudo":  true,
	"doas":  true,
	"runas": true,
}

// sudoValueFlags is the closed list of sudo / doas flags that
// take a value in the very next token. The sudo standard explicitly
// names `-u` (and the long form `--user`). The other half — `-h`,
// `-p`, `-g` — are also standard; missing one is a quiet
// "elevator-only" classification, never wrong.
// The colon form (`-u:root`) and the equals form (`-u=root`)
// are handled separately.
var sudoValueFlags = map[string]bool{
	"u": true, "user": true,
	"g": true, "group": true,
	"h": true, "host": true,
	"p": true, "prompt": true,
}

// elevatorReadFlags is the closed list of sudo / doas / runas
// flags whose only effect is to read state — list allowed
// commands, show version, show help. `sudo -l` is the canonical
// example; the others are the same kind and are
// bundled here for symmetry. They are NOT consumed by
// `elevatorCommand` — they become the inner "command" so the
// caller can return green for them.
var elevatorReadFlags = map[string]bool{
	"l": true, "list": true,
	"v": true, "version": true,
	"help": true,
}

// elevatorCommand strips a leading privilege elevator
// (`sudo`/`doas`/`runas`) and its standard flags, returning the
// command text that follows. The text-only stripper:
//
//   - consumes the elevator word,
//   - skips `-u user` / `--user user` (and the other value-taking
//     flags in `sudoValueFlags`) by reading the next token too,
//   - skips boolean flags like `-i`, `-s`, `-n` one token at a time,
//   - stops at `--`, treating everything after it as the command,
//   - recognizes `env FOO=1 …` and skips the env prefix and all
//     `VAR=value` tokens that follow until the next non-env arg,
//   - stops at the first non-flag / non-env token — that's the
//     command.
//
// Returns the stripped command text and `true` when an elevator
// was present. Otherwise returns the original part and `false`.
func elevatorCommand(part string) (string, bool) {
	trimmed := strings.TrimLeft(part, " \t")
	cmd := strings.ToLower(firstWord(trimmed))
	if !elevatorCommandNames[cmd] {
		return part, false
	}
	rest := strings.TrimLeft(trimmed[len(cmd):], " \t")
	for {
		if rest == "" {
			return "", true
		}
		toks := tokens(rest)
		if len(toks) == 0 {
			return "", true
		}
		tok := toks[0]
		// `--` ends the flag list; everything after is the command.
		if tok == "--" {
			idx := strings.Index(rest, tok) + len(tok)
			return strings.TrimLeft(rest[idx:], " \t"), true
		}
		// Read-only flag-verbs (`-l`, `--version`, `--help`)
		// are kept as the inner "command" so the caller can
		// return green for them.
		if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "/") {
			flagName := strings.ToLower(strings.TrimLeft(strings.TrimPrefix(tok, "/"), "-"))
			if elevatorReadFlags[flagName] {
				return strings.TrimLeft(rest, " \t"), true
			}
		}
		// Non-flag, non-prefix arg.
		if !strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "/") {
			// `sudo env FOO=1 cmd` — strip the env prefix and any
			// VAR=value tokens that follow it. The command after
			// `env` may itself start with letters.
			if strings.ToLower(tok) == "env" {
				idx := strings.Index(rest, tok) + len(tok)
				rest = strings.TrimLeft(rest[idx:], " \t")
				for {
					toks := tokens(rest)
					if len(toks) == 0 {
						return "", true
					}
					if !strings.Contains(toks[0], "=") {
						break
					}
					idx := strings.Index(rest, toks[0]) + len(toks[0])
					rest = strings.TrimLeft(rest[idx:], " \t")
				}
				continue
			}
			// Otherwise the positional token is the command.
			idx := strings.Index(rest, tok)
			if idx >= 0 {
				return strings.TrimLeft(rest[idx:], " \t"), true
			}
			return strings.TrimLeft(rest, " \t"), true
		}
		// A flag. Strip it; if it carries a value (`-u USER`,
		// `--user USER`), skip the next token too.
		lower := strings.ToLower(strings.TrimLeft(strings.TrimPrefix(tok, "/"), "-"))
		idx := strings.Index(rest, tok) + len(tok)
		rest = strings.TrimLeft(rest[idx:], " \t")
		// Colon / equals form: value is on the same token. Already
		// consumed when we sliced the flag off above.
		if strings.Contains(tok, "=") || strings.Contains(tok, ":") {
			continue
		}
		if sudoValueFlags[lower] {
			// Skip the value token if any.
			toks := tokens(rest)
			if len(toks) > 0 {
				idx := strings.Index(rest, toks[0]) + len(toks[0])
				rest = strings.TrimLeft(rest[idx:], " \t")
			}
			continue
		}
		// Boolean flag (e.g. -i, -s, -n, -E). Already consumed
		// the flag token above; loop continues to next token.
	}
}

// ruleSudoAtStartAtDepth is the elevator-as-prefix path.
//
// Per FIX-2, the elevator (sudo / doas / runas) is *transparent*
// by default: it talks about privileges, not about consequence.
// `sudo systemctl status nginx` is green because `systemctl
// status nginx` is green. `sudo rm -rf /var/lib/postgresql` is
// red because the inner command is red. The only exception is
// when the elevator opens a privileged shell with no command at
// all (`sudo`, `sudo -i`, `sudo -s`, `sudo bash`, `sudo su`),
// which is yellow because the next command in the same session
// will run as root with no further inspections to gate it. The
// pure-read exception (`sudo -l` lists allowed commands) stays
// green.
//
// The rule name `sudo-at-start` is retained from the first
// delivery for wire-format stability, but the verdict it
// reports is now driven by the inner command (or by the
// bare-shell / read-side white-lists below), never by the
// presence of the prefix alone.
func ruleSudoAtStartAtDepth(part string, wrapperDepth int) (Verdict, bool) {
	inner, has := elevatorCommand(part)
	if !has {
		return Verdict{}, false
	}
	innerTrimmed := stripCommandQuotes(strings.TrimSpace(inner))
	innerLower := strings.ToLower(innerTrimmed)
	switch innerLower {
	case "":
		// Bare `sudo` — opens a root shell with no command in
		// front of us. Yellow.
		return Verdict{
			Level:   Yellow,
			Rule:    "sudo-at-start",
			Reason:  "sudo (without a command) opens a root shell — subsequent commands in the same session will also run as root",
			Matched: true,
		}, true
	case "-i", "-s", "--login", "--shell":
		// Explicit login / shell forms.
		return Verdict{
			Level:   Yellow,
			Rule:    "sudo-at-start",
			Reason:  "sudo " + innerLower + " opens a privileged shell — subsequent commands in the same session will also run as root",
			Matched: true,
		}, true
	case "bash", "sh", "zsh", "fish", "ash", "ksh":
		// Shell explicitly named.
		return Verdict{
			Level:   Yellow,
			Rule:    "sudo-at-start",
			Reason:  "sudo runs " + innerLower + " as root — subsequent commands in this shell will also run as root",
			Matched: true,
		}, true
	case "su", "-su", "--su":
		// `sudo su` and friends — also opens a root session.
		return Verdict{
			Level:   Yellow,
			Rule:    "sudo-at-start",
			Reason:  "sudo runs " + innerLower + " — subsequent commands in this session will also run as root",
			Matched: true,
		}, true
	case "-l", "--list":
		// `sudo -l` reads the list of allowed commands; this is
		// informational and changes no state.
		return Verdict{
			Level:   Green,
			Rule:    "sudo-at-start",
			Reason:  "sudo " + innerLower + " reads the list of allowed commands — reversible and does not change state",
			Matched: true,
		}, true
	case "-v", "-V", "--version":
		// `sudo -v` updates sudo's own timestamp; `sudo -V`
		// and `sudo --version` print the version. All benign.
		return Verdict{
			Level:   Green,
			Rule:    "sudo-at-start",
			Reason:  "sudo " + innerLower + " — a sudo help or timestamp command that does not change other state",
			Matched: true,
		}, true
	case "--help":
		return Verdict{
			Level:   Green,
			Rule:    "sudo-at-start",
			Reason:  "sudo " + innerLower + " — a sudo help command that does not change other state",
			Matched: true,
		}, true
	}
	// Otherwise the elevator is transparent: classify the inner
	// command exactly as if `sudo` weren't there. The verdict's
	// `Matched` reflects what the inner-rule stack produced.
	return wrapCommandVerdict(strings.ToLower(firstWord(part)), classifyCommand(innerTrimmed, wrapperDepth+1)), true
}

// ── msiexec, Start-Process -Verb RunAs ──

func ruleInstallOrElevate(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	switch cmd {
	case "msiexec":
		return Verdict{
			Level:   Yellow,
			Rule:    "msi-install",
			Reason:  "msiexec launches a Windows Installer installation — it changes the system and registry",
			Matched: true,
		}, true
	case "start-process":
		lower := strings.ToLower(part)
		if strings.Contains(lower, "-verb runas") {
			return Verdict{
				Level:   Yellow,
				Rule:    "elevate-start-process",
				Reason:  "Start-Process -Verb RunAs launches an elevated process (UAC)",
				Matched: true,
			}, true
		}
	}
	return Verdict{}, false
}

// ── writes to system paths ──

// systemRedirect matches a redirect-style write (`>`, `>>`, `2>`,
// `&>`) directly into a system directory. It is split from the
// cmdlet form below because PowerShell uses `-FilePath` / `-Path`
// flags between the cmdlet and its argument, which would not be
// captured by a single regex.
var systemRedirect = regexp.MustCompile(
	`(?i)(?:>>?\s?|2>?\s?|&\s?>?\s?)` +
		`[` + "`" + `"']?` +
		`(?:[a-z]:\\[Ww][Ii][Nn][Dd][Oo][Ww][Ss](?:\\[^"'\s` + "`" + `]*)?` +
		`|[a-z]:\\[Pp]rogram\s?[Ff]iles(?:[\\](?:\(x86\))?)?(?:\\[^"'\s` + "`" + `]*)?` +
		`|[a-z]:\\[Pp]rogram[Dd]ata(?:\\[^"'\s` + "`" + `]*)?` +
		`|/(?:etc|usr|var|boot|sbin|lib|sys)(?:/[^"'\s` + "`" + `]+)?)`,
)

// systemDirSubstrs lists each system-directory pattern as it
// appears inside a PowerShell argument. `Set-Content -Path
// "C:\Windows\foo"` lowercased contains "c:\windows" — substring
// detection is enough for the cmdlet case because the cmdlet
// names (`out-file`, `set-content`, …) are themselves the rare
// half of the heuristic.
var systemDirSubstrs = []string{
	`c:\windows`,
	`c:/windows`,
	`c:\program files`,
	`c:/program files`,
	`c:\programdata`,
	`c:/programdata`,
	`/etc/`,
	`/usr/`,
	`/var/`,
	`/boot/`,
	`/sbin/`,
	`/sys/`,
}

// writeCmdlets is the closed list of first-word verbs whose
// intent is "write a file". Read-only cmds (`Get-Content`) are
// not in this list and won't fire the rule.
var writeCmdlets = map[string]bool{
	"out-file":        true,
	"set-content":     true,
	"add-content":     true,
	"copy-item":       true,
	"tee":             true,
	"cp":              true,
	"mv":              true,
	"set-itemcontent": true,
	"add-itemcontent": true,
}

// ruleSystemDirWrite reports a write into a system directory. The
// command is checked two ways: (a) the first word is a write
// cmdlet/command AND the rest contains a system-dir substring,
// (b) a redirect operator points straight into a system dir. False
// positives here just nudge a near-green command to yellow.
func ruleSystemDirWrite(part string) (Verdict, bool) {
	cmd := strings.ToLower(firstWord(part))
	// Doubled backslashes are PowerShell-quoted paths and test
	// inputs both; collapse for the substring check.
	lower := multiBackslashRe.ReplaceAllString(strings.ToLower(part), `\`)
	if writeCmdlets[cmd] {
		for _, p := range systemDirSubstrs {
			if strings.Contains(lower, p) {
				return Verdict{
					Level:   Yellow,
					Rule:    "system-dir-write",
					Reason:  "writing to a system directory (C:\\Windows, C:\\Program Files, /etc, /usr, /var, /boot, etc.) — changes the OS",
					Matched: true,
				}, true
			}
		}
	}
	if systemRedirect.MatchString(part) {
		return Verdict{
			Level:   Yellow,
			Rule:    "system-dir-write",
			Reason:  "writing to a system directory (C:\\Windows, C:\\Program Files, /etc, /usr, /var, /boot, etc.) — changes the OS",
			Matched: true,
		}, true
	}
	return Verdict{}, false
}

// isSystemRootPath reports whether `p` is the filesystem root of
// the OS (`/`, `\\?\C:\`, `C:\`, etc.). Used by Red rules for
// chmod/chown and by the rm root carve-out.
func isSystemRootPath(p string) bool {
	p = stripQuotes(p)
	if p == "" {
		return false
	}
	lower := strings.ToLower(p)
	switch lower {
	case "/", "//", "/.",
		`c:\`, `c:/`, `c:\\`,
		`c:`, // ambiguous, but matches `cd /` ergonomics
		"":
		return true
	}
	if strings.HasSuffix(p, ":\\") || strings.HasSuffix(p, ":/") {
		return true
	}
	return false
}
