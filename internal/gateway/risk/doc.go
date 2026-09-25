// Package risk is the pre-flight classifier that looks at a shell command
// the SSH agent is about to send and says how bad the consequence would be
// if the command actually ran. It is deliberately a second-class guard:
// a textual classifier against accidental stupidity, not a
// security boundary against a malicious actor — anyone can bypass it in a
// second (base64, here-string, an uploaded script). The point is that the
// owner runs an unattended agent and wants a low false-positive rate on
// ordinary reconnaissance so they don't tear the whole thing down after a
// week of yellow alerts on `journalctl` and `Get-Service`.
//
// The package has no dependencies and imports nothing from the rest of the
// repository on purpose: it is a leaf, callable from anywhere, and tested
// in isolation. The decisions are entirely consequence-based ("does this
// destroy data or cut the owner off the machine?") rather than aesthetic
// ("does this command feel scary?"). The constants Green/Yellow/Red carry
// the definitions.
//
// # Verdict and Matched
//
// Verdict.Level is the worst-case consequence across the parts of the
// command, taken by `;`, `&&`, `||`, and `|` outside quotes. Rule and
// Reason are taken from the rule that produced the worst level. Verdict
// .Matched is the seam between this package and the next: true means a
// rule looked at the command and produced a verdict (including a green
// one — `rm -rf /tmp/build` is `Green+Matched`), false means no rule
// recognized the command at all and the next layer (an external AI
// classifier, when it exists) gets to decide.
package risk
