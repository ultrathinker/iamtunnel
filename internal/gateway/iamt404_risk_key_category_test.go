package gateway

// IAMT-404 canary: the risk.key refusal names its failure class in a
// machine-readable category beside the prose, and the class agrees with
// the sentence — "rejected" exactly when the service answered and said
// no, "unavailable" when the trial was inconclusive. The window used to
// recover this distinction by substring-reading the gateway's sentence
// (cmd/iamtunnel/gui_actions.go), one rewording away from telling a
// person with a dead key to retry later forever; the reply now says it
// directly, and this canary holds the wire promise and the prose
// agreement together.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// iamt404ReplyChan is just enough ssh.Channel for finishCommand to write
// its §1.2 envelope line into a buffer.
type iamt404ReplyChan struct {
	bytes.Buffer
	stderr bytes.Buffer
}

func (c *iamt404ReplyChan) Close() error                                   { return nil }
func (c *iamt404ReplyChan) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (c *iamt404ReplyChan) CloseWrite() error                              { return nil }
func (c *iamt404ReplyChan) Stderr() io.ReadWriter                          { return &c.stderr }

func TestIAMT404_TheRiskKeyReplyNamesTheFailureCategory(t *testing.T) {
	cases := []struct {
		name  string
		probe error
		want  string
	}{
		{"the service answered and said no",
			risk.NewExternalClassifierError(risk.ExternalFailureAuthentication, 401, errors.New("denied")),
			"rejected"},
		{"the service could not be reached",
			risk.NewExternalClassifierError(risk.ExternalFailureUnavailable, 503, errors.New("busy")),
			"unavailable"},
		{"the service never answered", context.DeadlineExceeded, "unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "classifier.key")
			if err := os.WriteFile(keyPath, []byte("old-classifier-test-key\n"), 0o600); err != nil {
				t.Fatalf("write old key: %v", err)
			}
			f := newFixture(t, func(c *Config) {
				c.RiskClassifier = RiskClassifierAI
				c.ExternalRiskObservationKeyFile = keyPath
				c.externalRiskClassifierFactory = func(key string) risk.ExternalClassifier {
					return &iamt403KeyClassifier{err: tc.probe}
				}
			})
			addPerson(t, f, "root", "admin", genSigner(t))

			_, cerr := f.gw.runCommand("root", "risk.key", []byte(`{"proto":1,"key":"new-classifier-test-key"}`))
			if cerr == nil || cerr.code != "E_RISK_KEY_REJECTED" {
				t.Fatalf("risk.key = %#v, want E_RISK_KEY_REJECTED", cerr)
			}
			if cerr.category != tc.want {
				t.Fatalf("the risk.key refusal names category %q, want %q — the reply carries no machine-readable class (IAMT-404)", cerr.category, tc.want)
			}

			// The reply the gateway actually writes carries the same class
			// in the §1.2 error body.
			ch := &iamt404ReplyChan{}
			f.gw.finishCommand(ch, nil, cerr)
			var env struct {
				Error struct {
					Code     string `json:"code"`
					Message  string `json:"message"`
					Category string `json:"category"`
				} `json:"error"`
			}
			if err := json.Unmarshal(bytes.TrimRight(ch.Bytes(), "\n"), &env); err != nil {
				t.Fatalf("reply is not the §1.2 envelope: %v (%s)", err, ch.String())
			}
			if env.Error.Category != tc.want {
				t.Fatalf("the wire envelope's error body carries category %q, want %q (IAMT-404)", env.Error.Category, tc.want)
			}

			// The field and the prose must agree while both exist: the
			// category is "rejected" exactly when the sentence says so, so
			// a window too old for the field reads the same truth from the
			// words it has.
			if (env.Error.Category == "rejected") != strings.Contains(env.Error.Message, "rejected by the classifier service") {
				t.Fatalf("category %q and reason %q disagree about what happened to the key", env.Error.Category, env.Error.Message)
			}
		})
	}
}
