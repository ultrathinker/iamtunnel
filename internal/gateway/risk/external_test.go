package risk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExternalClassifier_ScrubsCommandAndAsksAllQuestions(t *testing.T) {
	var request externalRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want bearer key", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		reply := answerEveryQuestion(0.1)
		reply["answers"].(map[string]any)["access"] = map[string]any{"noul": 0.3}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer server.Close()

	client := newExternalClassifier("test-key", server.URL, server.Client())
	assessment, err := client.Classify(context.Background(), "curl -p secret --password=hunter2 --token=abc -u user:pass -H 'Authorization: Bearer topsecret' AAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if request.Model != externalClassifierModel || len(request.Questions) != len(externalQuestions) {
		t.Fatalf("request = %+v, want model and every question", request)
	}
	for key := range externalQuestions {
		if _, ok := request.Questions[key]; !ok {
			t.Errorf("request missing question %q", key)
		}
	}
	for _, secret := range []string{"secret", "hunter2", "abc", "user:pass", "topsecret", "AAAAAAAAAAAAAAAAAAAAAAAA"} {
		if strings.Contains(request.State, secret) {
			t.Errorf("scrubbed state leaks %q: %q", secret, request.State)
		}
	}
	if assessment.Scores["access"] != 0.3 {
		t.Errorf("access score = %v, want 0.3", assessment.Scores["access"])
	}
}

func TestExternalClassifier_GoalIsNamedAndScrubbedInOneState(t *testing.T) {
	var request externalRequest
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(answerEveryQuestion(0.1))
	}))
	defer server.Close()

	client := newExternalClassifier("test-key", server.URL, server.Client())
	_, err := client.ClassifyWithGoal(context.Background(),
		"rm -rf /var/lib/data --password=command-secret",
		"keep the site online --token=goal-secret", nil)
	if err != nil {
		t.Fatalf("ClassifyWithGoal: %v", err)
	}
	if requests != 1 {
		t.Fatalf("classifier requests = %d, want one request carrying both facts", requests)
	}
	var got externalState
	if err := json.Unmarshal([]byte(request.State), &got); err != nil {
		t.Fatalf("state is not named JSON: %q: %v", request.State, err)
	}
	if got.Command != "rm -rf /var/lib/data --password=<redacted>" {
		t.Errorf("state command = %q, want scrubbed command", got.Command)
	}
	if got.Goal != "keep the site online --token=<redacted>" {
		t.Errorf("state goal = %q, want scrubbed goal", got.Goal)
	}
	for _, secret := range []string{"command-secret", "goal-secret"} {
		if strings.Contains(request.State, secret) {
			t.Errorf("state leaks %q: %q", secret, request.State)
		}
	}
}

func TestScrubCommand_PreservesPathsAndDelimiters(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		{"rm -rf /var/lib/postgresql/data", "rm -rf /var/lib/postgresql/data"},
		{"ls -la /srv/www/production/releases/current", "ls -la /srv/www/production/releases/current"},
		{"curl -H \"Authorization: Bearer abc\" https://x/y", "curl -H \"Authorization: <redacted>\" https://x/y"},
		{"systemctl restart postgresql", "systemctl restart postgresql"},
		{"curl https://example.test/api/v1/health", "curl https://example.test/api/v1/health"},
		{"tool -p\u041f\u0430\u0440\u043e\u043b\u044c", "tool -p<redacted>"},
		{"tool --password=verysecret", "tool --password=<redacted>"},
		{"tool token=AAAAAAAAAAAAAAAAAAAAAAAA", "tool token=<redacted>"},
		{"curl -H \"Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAA\" https://x/y", "curl -H \"Authorization: <redacted>\" https://x/y"},
	} {
		if got := ScrubCommand(tc.command); got != tc.want {
			t.Errorf("ScrubCommand(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}

func TestCanary_B5_ScrubSecretFormsTable(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    string
	}{
		{"password equals", "tool --password=hunter2", "tool --password=<redacted>"},
		{"password whitespace", "tool --password hunter2", "tool --password <redacted>"},
		{"token whitespace", "tool --token abc", "tool --token <redacted>"},
		{"api key whitespace", "tool --api-key abc", "tool --api-key <redacted>"},
		{"secret whitespace", "tool --secret abc", "tool --secret <redacted>"},
		{"aws access key", "tool --aws-access-key-id AKIA123", "tool --aws-access-key-id <redacted>"},
		{"aws secret key", "tool --aws-secret-access-key abc", "tool --aws-secret-access-key <redacted>"},
		{"short user", "tool -u user:pass", "tool -u <redacted>"},
		{"postgres environment", "PGPASSWORD=postgres-secret psql", "PGPASSWORD=<redacted> psql"},
		{"mysql environment", "MYSQL_PWD=mysql-secret mysql", "MYSQL_PWD=<redacted> mysql"},
		{"token environment", "DEPLOY_TOKEN=token-value deploy", "DEPLOY_TOKEN=<redacted> deploy"},
		{"secret environment", "SERVICE_SECRET=secret-value service", "SERVICE_SECRET=<redacted> service"},
		{"key environment", "SERVICE_KEY=key-value service", "SERVICE_KEY=<redacted> service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScrubCommand(tc.command); got != tc.want {
				t.Fatalf("ScrubCommand(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

func TestUpgradeWithExternalOpinionCanReturnRed(t *testing.T) {
	local := Verdict{Level: Green, Matched: false}
	low := ExternalAssessment{Scores: map[string]float64{"destroys": ExternalRiskThreshold}}
	if got := UpgradeWithExternalOpinion(local, low); got.Level != Green {
		t.Errorf("threshold score verdict = %s, want green", got.Level)
	}
	high := ExternalAssessment{Scores: map[string]float64{
		"destroys": 0.99, "access": 0.99,
	}}
	if got := UpgradeWithExternalOpinion(local, high); got.Level != Red || got.Rule != "external-classifier" {
		t.Errorf("all high scores verdict = %+v, want external red", got)
	}
	matched := Verdict{Level: Red, Matched: true}
	if got := UpgradeWithExternalOpinion(matched, high); got != matched {
		t.Errorf("matched local verdict changed to %+v", got)
	}
}

func TestExternalClassifier_HTTPFailureReturnsTypedError(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   ExternalFailureKind
	}{
		{http.StatusUnauthorized, ExternalFailureAuthentication},
		{http.StatusForbidden, ExternalFailureAuthentication},
		{http.StatusTooManyRequests, ExternalFailureUnavailable},
		{http.StatusInternalServerError, ExternalFailureUnavailable},
	} {
		status, wantKind := tc.status, tc.kind
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			_, err := newExternalClassifier("key", server.URL, server.Client()).Classify(context.Background(), "unknown-command")
			if err == nil {
				t.Fatalf("Classify status %d succeeded, want error", status)
			}
			if got := ExternalFailureKindOf(err); got != wantKind {
				t.Fatalf("Classify status %d kind = %q, want %q", status, got, wantKind)
			}
			if got := ExternalFailureStatusCode(err); got != status {
				t.Fatalf("Classify status %d recorded status = %d", status, got)
			}
		})
	}
}

func TestExternalClassifier_TimeoutIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := newExternalClassifier("key", server.URL, server.Client()).Classify(ctx, "unknown-command")
	if err == nil {
		t.Fatal("Classify timeout succeeded, want error")
	}
	if got := ExternalFailureKindOf(err); got != ExternalFailureUnavailable {
		t.Fatalf("timeout kind = %q, want %q", got, ExternalFailureUnavailable)
	}
	if !ExternalFailureTimedOut(err) {
		t.Fatalf("timeout error = %v, want context deadline", err)
	}
}

// answerEveryQuestion replies to whatever the client actually asked, rather
// than to a list written down here.
//
// A hard-coded pair of answers is a test that goes stale the day a question
// is added, and it did: adding "unrelated" and "tampering" (21.09.2026) made
// these doubles return two answers to a four-question request, and the
// client rejected the response for a missing probability. The client is
// right to be strict -- a missing answer is a question nobody judged -- so
// the double follows the request instead.
func answerEveryQuestion(score float64) map[string]any {
	answers := map[string]any{}
	for name := range externalQuestions {
		answers[name] = map[string]any{"noul": score}
	}
	return map[string]any{"answers": answers}
}
