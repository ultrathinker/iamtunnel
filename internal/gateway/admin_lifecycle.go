package gateway

// admin_lifecycle.go serves the two lifecycle commands of the admin
// exec surface (PROTOCOL §6): gateway.backup and gateway.rotate-hostkey.
// They are thin front ends over internal/gateway/lifecycle.go — the
// same implementation the local "iamtunnel gateway backup" /
// "gateway rotate-hostkey" verbs run — so a remote administrator and an
// operator on the gateway box get byte-for-byte the same artifacts (an
// archive in the gateway's own storage; a rotated key with the old one
// kept at hostkey.old and a hostkey.rotate journal event).
//
// These handlers were the missing half of IAMT-162 finding G3 / IAMT-174:
// the client library already sent both commands, the gateway answered
// E_EXEC_UNKNOWN.

import (
	"time"
)

// backupView is the `backup` object of gateway.backup's PROTOCOL §6
// result. Field names mirror internal/admin's GatewayBackup decoder,
// which parses strictly (DisallowUnknownFields) — the two must stay in
// lockstep field for field.
type backupView struct {
	ID      string `json:"id"`
	Created string `json:"created"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

func cmdGatewayBackup(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if g.cfg.DataDir == "" {
		return nil, errf("E_INTERNAL", 70, "gateway data directory is not configured; remote backup is unavailable")
	}
	id, _, size, sum, err := CreateBackupArchive(g.cfg.DataDir, now)
	if err != nil {
		g.logAdminOp(person, "gateway.backup", id, "failed", map[string]interface{}{"err": err.Error()})
		return nil, errf("E_INTERNAL", 70, "gateway.backup: %v", err)
	}
	g.logAdminOp(person, "gateway.backup", id, "ok", map[string]interface{}{"size": size, "sha256": sum})
	return map[string]any{"backup": backupView{
		ID:      id,
		Created: rfc3339(now),
		Size:    size,
		SHA256:  sum,
	}}, nil
}

func cmdGatewayRotateHostkey(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if g.cfg.DataDir == "" {
		return nil, errf("E_INTERNAL", 70, "gateway data directory is not configured; host key rotation is unavailable")
	}
	oldFP, newFP, err := RotateHostKey(g.cfg.DataDir, g.cfg.Log, now)
	if err != nil {
		g.logAdminOp(person, "gateway.rotate-hostkey", "hostkey", "failed", map[string]interface{}{"err": err.Error()})
		return nil, errf("E_INTERNAL", 70, "gateway.rotate-hostkey: %v", err)
	}
	// The running process keeps presenting the OLD key until it is
	// restarted (RUNBOOK §4.3 step 2: restart the gateway service to apply
	// the new key) — cfg.HostKey is deliberately not swapped
	// under a live listener; peers mid-handshake would see a key that
	// matches neither the old pin nor the new one. The response carries
	// the on-disk new fingerprint the restarted gateway will present.
	g.logAdminOp(person, "gateway.rotate-hostkey", "hostkey", "ok", map[string]interface{}{
		"oldFingerprint": oldFP, "newFingerprint": newFP,
	})
	return map[string]string{"oldFingerprint": oldFP, "newFingerprint": newFP}, nil
}
