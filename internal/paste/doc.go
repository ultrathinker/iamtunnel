// Package paste is the single parser behind the single field of SPEC
// §3.6: "one string, one field". It takes whatever a person actually
// pasted — the canonical iamtunnel-claim:// / iamtunnel-pair:// /
// iamtunnel-enrol:// / iamtunnel:// string, the whole command line the
// gateway printed around it, a bare "<host>:<port>#<fingerprint>"
// reference with the PIN next to it, any of those in quotes, indented,
// or with the sentence the gateway printed above them — and says what
// it is, or refuses in words that name what was actually wrong.
//
// The grammars themselves live in internal/config (ParseClaimRef,
// ParsePairingRef, ParseEnrolCode, ParseConnString) and are NOT
// repeated here: this package strips the wrapper a human added and
// hands the substance to the one parser that already owns that shape.
// Refusals are config.Error of class config.ClassUser, so the CLI exit
// code is the same whether the string came from a field or an argument.
//
// The package holds no state, opens no files and reaches no network:
// Parse decides what the paste is, Preview says it in one sentence, and
// only the caller's button acts (SPEC §3.6, "preview is mandatory").
package paste
