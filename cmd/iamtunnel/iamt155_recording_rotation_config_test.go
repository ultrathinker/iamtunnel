package main

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// TestIAMT155_ProductionRecordingRotationSettingsReachRuntime guards the
// production seam: settings must pass through config.Load and then through
// gatewayRuntimeConfig, not be re-created by gateway tests that construct a
// Config directly.
func TestIAMT155_ProductionRecordingRotationSettingsReachRuntime(t *testing.T) {
	settings, err := config.Load("linux", map[string]string{"HOME": "/h"}, config.Override{}, func(string) ([]byte, error) {
		// Deliberately not the defaults: a hard-coded 90/85 would also be a
		// broken production seam. Both values are valid positive settings.
		return []byte(`{"recordings_retention_days":17,"recordings_disk_stop_percent":71}`), nil
	})
	if err != nil {
		t.Fatalf("config.Load recording rotation settings: %v", err)
	}
	if settings.RecordingsRetentionDays <= 0 {
		t.Fatalf("config.Load RecordingRetentionDays = %d; zero disables age rotation", settings.RecordingsRetentionDays)
	}
	if settings.RecordingsDiskStopPercent <= 0 {
		t.Fatalf("config.Load RecordingDiskStopPercent = %d; zero disables size rotation", settings.RecordingsDiskStopPercent)
	}

	runtime := gatewayRuntimeConfig(nil, nil, nil, t.TempDir(), settings)
	if got, want := runtime.RecordingRetentionDays, settings.RecordingsRetentionDays; got != want {
		t.Fatalf("gatewayRuntimeConfig RecordingRetentionDays = %d, want settings.RecordingsRetentionDays=%d", got, want)
	}
	if got := runtime.RecordingRetentionDays; got <= 0 {
		t.Fatalf("gatewayRuntimeConfig RecordingRetentionDays = %d; zero disables age rotation", got)
	}
	if got, want := runtime.RecordingRotatePercent, settings.RecordingsDiskStopPercent; got != want {
		t.Fatalf("gatewayRuntimeConfig RecordingRotatePercent = %d, want settings.RecordingsDiskStopPercent=%d", got, want)
	}
	if got := runtime.RecordingRotatePercent; got <= 0 {
		t.Fatalf("gatewayRuntimeConfig RecordingRotatePercent = %d; zero disables size rotation", got)
	}
}
