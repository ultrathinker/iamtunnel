// Package acl answers exactly one question: may person X enter machine Y
// right now - and makes a permission that stops applying tear live
// sessions down immediately (SPEC 3.3, 4.3, 5.1, 6.4). Decisions are
// typed, denials carry a DenyReason, deadlines are validated on entry,
// and every time value is injected as an argument from the gateway's UTC
// clock - nothing here calls time.Now, touches files, network or SSH.
// Gateway state is read through the View interface so the state package
// stays the single owner of storage; session counters and notification
// subscriptions are the only runtime state this package holds.
package acl
