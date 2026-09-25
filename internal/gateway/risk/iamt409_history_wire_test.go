package risk

// IAMT-409: the recent-command buffer travels outward in the request's
// STATE to the classifier — as a separate named history field, not as
// prose inside the command. The scrub is done by the gateway at the
// moment the buffer is WRITTEN, so the wire carries the entries as stored.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIAMT409_ClassifierRequestCarriesRecentCommandHistory(t *testing.T) {
	var request externalRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(answerEveryQuestion(0.1))
	}))
	defer server.Close()

	client := newExternalClassifier("test-key", server.URL, server.Client())
	history := []RecentCommandContext{
		{Command: "copy car.jpg C:\\Users\\Admin\\Desktop", Exit: "0", Response: "1 file(s) copied."},
		{Command: "del C:\\car.jpg --token=<redacted>", Exit: "0", Response: ""},
	}
	if _, err := client.ClassifyWithGoal(context.Background(), "del C:\\car.jpg", "", history); err != nil {
		t.Fatalf("ClassifyWithGoal: %v", err)
	}
	if len(request.Questions) != len(externalQuestions) {
		t.Fatalf("questions in the request = %d, want %d", len(request.Questions), len(externalQuestions))
	}
	var got externalState
	if err := json.Unmarshal([]byte(request.State), &got); err != nil {
		t.Fatalf("state is not named JSON: %q: %v", request.State, err)
	}
	if len(got.History) != 2 {
		t.Fatalf("history in the request state = %v, want two entries", got.History)
	}
	if got.History[0].Command != "copy car.jpg C:\\Users\\Admin\\Desktop" ||
		got.History[0].Exit != "0" ||
		got.History[0].Response != "1 file(s) copied." {
		t.Errorf("first history entry is distorted: %+v", got.History[0])
	}
	if got.History[1].Command != "del C:\\car.jpg --token=<redacted>" {
		t.Errorf("second history entry is distorted: %+v", got.History[1])
	}
}

func TestIAMT409_ClassifierWithoutGoalStillAnswersWithoutHistory(t *testing.T) {
	var request externalRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(answerEveryQuestion(0.1))
	}))
	defer server.Close()

	client := newExternalClassifier("test-key", server.URL, server.Client())
	if _, err := client.Classify(context.Background(), "ls"); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	// The legacy path sends state as the bare scrubbed command string, with
	// no named JSON and no history — only the full request carries history.
	if request.State != "ls" {
		t.Errorf("state of the legacy request = %q, want the bare command without history", request.State)
	}
	if strings.Contains(request.State, "history") {
		t.Errorf("the legacy Classify call must not carry history: %q", request.State)
	}
}
