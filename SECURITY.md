# Security policy

## Supported versions

Only the latest tagged release is supported. Security fixes land on `main` and
ship in the next release; there are no maintained older branches.

## Reporting a vulnerability

Please report security issues privately through **GitHub Private Vulnerability
Reporting** (this repository's Security tab → "Report a vulnerability"). Do not
open a public issue for a suspected vulnerability.

Include what you found, how to reproduce it, and the version (`iamtunnel
version`) you tested against. This is a young project maintained by one
person, so response times vary — expect an initial reply within a few days.

## Trust boundary, briefly

iamtunnel's gateway is a trusted bastion: it terminates SSH on both sides so it
can record sessions, which means the gateway process sees session plaintext
and holds the ephemeral door keys in memory while a door is open. Full
compromise of the gateway host (root or the `iamtunnel` service account) is
outside what the design defends against — see `docs/THREATS.md` for the full
model, what is and isn't defended, and the accepted residual risks.

If you find a way to defeat a boundary that `docs/THREATS.md` claims holds
(for example, reading another person's session, opening a door without a
grant, or forging a journal entry without gateway-level access), that is a
vulnerability worth reporting even if the underlying host is otherwise
trusted.
