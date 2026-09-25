// Package e2e hosts the in-process end-to-end suite: a gateway on
// loopback, a fake machine that runs its own sshd on x/crypto with an
// echo shell and a pty, and a client (SPEC §8). The scenarios land in
// phase 1; the skeleton only fixes the layout so the suite has a home.
package e2e
