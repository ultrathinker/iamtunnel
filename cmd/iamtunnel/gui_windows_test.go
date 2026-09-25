//go:build windows && !nogui

package main

// gui_windows_test.go covers the wiring in gui_windows.go directly — the
// glue between the live window and internal/client, with no window and
// no network involved. All directories are t.TempDir(): nothing here may
// touch a real %LOCALAPPDATA%\iamtunnel.

import (
	"context"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

// second connection string, distinct from the package's own connStr
// (main_test.go) so the "already saved" refusal has something different
// to refuse.
const connStr2 = "iamtunnel://127.0.0.1:2/bob#" + fpr43

// A second gateway pasted into the window is REMEMBERED, not refused
// (IAMT-431). Until 22.09.2026 the window refused it, because the file
// held one connection and the second would have destroyed the first.
func TestGuiSaveConnectionRemembersASecondGateway(t *testing.T) {
	dir := t.TempDir()
	if _, err := guiSaveConnection(dir, connStr, "", false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if _, err := guiSaveConnection(dir, connStr2, "", false); err != nil {
		t.Fatalf("a second gateway must need no Replace: %v", err)
	}

	set, err := client.LoadConnections(dir)
	if err != nil {
		t.Fatalf("LoadConnections: %v", err)
	}
	if len(set.Gateways) != 2 {
		t.Fatalf("the window saved %d gateways, want 2", len(set.Gateways))
	}
	got, lerr := client.LoadConnection(dir)
	if lerr != nil {
		t.Fatalf("LoadConnection: %v", lerr)
	}
	if got.Port != 2 {
		t.Errorf("current port = %d, want 2 (the one just pasted)", got.Port)
	}
}

// The guard that survives: the same door with a different key.
func TestGuiSaveConnectionRefusesAChangedGatewayKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := guiSaveConnection(dir, connStr, "", false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	rekeyed := strings.Replace(connStr, fpr43, strings.Repeat("B", 43), 1)
	if rekeyed == connStr {
		t.Fatal("the test did not actually change the fingerprint")
	}

	_, err := guiSaveConnection(dir, rekeyed, "", false)
	if err == nil {
		t.Fatal("guiSaveConnection(replace=false) accepted a CHANGED GATEWAY KEY without a word")
	}
	if !strings.Contains(err.Error(), "--replace") {
		t.Errorf("error = %q, want it to name --replace", err.Error())
	}

	got, lerr := client.LoadConnection(dir)
	if lerr != nil {
		t.Fatalf("LoadConnection after a refused re-key: %v", lerr)
	}
	if got.Fingerprint != "SHA256:"+fpr43 {
		t.Errorf("the refused re-key reached the disk: fingerprint = %q", got.Fingerprint)
	}
}

func TestGuiSaveConnectionReplaceOverwrites(t *testing.T) {
	dir := t.TempDir()
	if _, err := guiSaveConnection(dir, connStr, "", false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if _, err := guiSaveConnection(dir, connStr2, "", true); err != nil {
		t.Fatalf("guiSaveConnection(replace=true): %v", err)
	}

	got, err := client.LoadConnection(dir)
	if err != nil {
		t.Fatalf("LoadConnection after replace: %v", err)
	}
	if got.Port != 2 || got.Person != "bob" {
		t.Errorf("saved connection = %+v, want the replacement (port 2, person bob)", got)
	}
}

func TestGuiMachinesWithoutASavedConnectionSaysSo(t *testing.T) {
	dir := t.TempDir()

	_, err := guiMachines(context.Background(), dir)
	if err == nil {
		t.Fatalf("guiMachines with no saved connection did not fail")
	}
	if !strings.Contains(err.Error(), "no connection string saved yet") {
		t.Errorf("guiMachines error = %q, want the \"no connection string saved yet\" sentence", err.Error())
	}
}
