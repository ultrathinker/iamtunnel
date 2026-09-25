package gateway

// R3 F-02 of the round-3 review (24.09.2026), medium: the verdict on
// a command's own lost record (R2-CX F-03, round 2) matched the WATCHED
// wire name against the op in the journal line. Four commands break that
// equation and fell out of the invariant altogether:
//
//   - risk.key journals its line as risk.key.replace (the op is older than
//     the wire name), so a lost replacement was keyed under a name nobody
//     watched;
//   - risk.approve, risk.deny and sessions.tail wrote no admin.op line at
//     all - their record is a typed event (risk.approval, session.watch),
//     and adminOpOf sees only admin.op lines.
//
// All four then answered "ok" for work whose record the journal lost: the
// approval is granted in memory and spent by the next matching command, so
// "approved: true" with no line saying who approved it is the loss nobody
// can reconstruct.
//
// The fix has two halves, and both are structural rather than per-case:
// the command table declares the ops each command writes about itself
// (risk.key declares its alias), and the three typed-event commands write
// their own admin.op line as well. The tests below sweep the WHOLE table
// rather than the four names, because this class has now been found three
// rounds running: every write command's record must be attributable, and
// every op the package journals must be declared by some command.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// roleOwnedOps are the ops written by a one-off role about itself rather
// than by a command: the pairing role's records (admin.pair when a person
// is created, pairing.burn when a window is burned by wrong PINs). They
// are watched actor-wide by runAuditedRole (R1-CX F-15), not per command,
// so they are nobody's ownRecords.
var roleOwnedOps = map[string]bool{
	"admin.pair":   true,
	"pairing.burn": true,
}

// TestR3F02_EveryWriteCommandsOwnRecordIsAttributed is the class, closed:
// for every command that writes, a lost line of the kind it writes about
// itself has to be attributed to that command - whatever the line is
// called and whether it is an admin.op line or a typed event.
func TestR3F02_EveryWriteCommandsOwnRecordIsAttributed(t *testing.T) {
	checked := 0
	for name, spec := range commandTable {
		if spec.readOnly {
			continue
		}
		ops := spec.ownRecords(name)
		if len(ops) == 0 {
			t.Errorf("command %q writes and declares no record of its own: its lost line would be nobody's and it would answer ok (F-02)", name)
			continue
		}
		for _, op := range ops {
			h := &auditHealth{}
			watch := h.watchCmd("root", []string{op})
			// What the command writes about itself: logAdminOp writes
			// "<op>:<result>" with the command's person as the actor.
			h.noteLost(events.Event{
				Type:   events.EventAdminOp,
				Actor:  "root",
				Object: "bob",
				Result: op + ":ok",
			})
			if !h.lostSince(watch) {
				t.Errorf("command %q declares %q as its own record and the loss of that line is not attributed to it: it would answer ok for work whose record is gone (F-02)", name, op)
			}
		}
		checked++
	}
	if checked < 20 {
		t.Fatalf("the sweep only looked at %d commands, which is too few for this table to be the whole command surface", checked)
	}
}

// noteLost folds one lost journal write into h, the way noteAudit does
// when a write fails - without the gateway around it, so the sweep above
// can ask the attribution question of every command in the table.
func (h *auditHealth) noteLost(e events.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.noteLostLocked(e)
}

// TestR3F02_EveryOpThePackageJournalsIsDeclared reads the sources of the
// package and checks the other direction: every op written through
// logAdminOp is declared by some command (its wire name by default, an
// alias where the command says so) or is a one-off role's own record.
// This is the half that catches a drift like risk.key/risk.key.replace -
// the table cannot see the code, and the code is where the name is
// written.
func TestR3F02_EveryOpThePackageJournalsIsDeclared(t *testing.T) {
	declared := map[string]bool{}
	for name, spec := range commandTable {
		if spec.readOnly {
			continue
		}
		for _, op := range spec.ownRecords(name) {
			declared[op] = true
		}
	}
	ops, err := r3OpsWrittenByLogAdminOp(t, ".")
	if err != nil {
		t.Fatalf("reading the package sources: %v", err)
	}
	if len(ops) < 20 {
		t.Fatalf("the scan found only %d op(s), so it is not reading the call sites: %v", len(ops), ops)
	}
	for op, where := range ops {
		if declared[op] || roleOwnedOps[op] {
			continue
		}
		t.Errorf("the package journals %q as an admin.op (%s) and no command declares it as its own record: a command whose line is called something other than its wire name has to declare it (commandSpec.auditOps), or the loss of that line is attributed to nobody (F-02)", op, where)
	}
}

// r3OpsWrittenByLogAdminOp collects the op argument of every logAdminOp
// CALL in the package's non-test sources, with the file it appears in.
func r3OpsWrittenByLogAdminOp(t *testing.T, dir string) (map[string]string, error) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	ops := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil, perr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "logAdminOp" || len(call.Args) < 2 {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			op, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			ops[op] = name
			return true
		})
	}
	return ops, nil
}

// TestR3F02_TheAliasedRecordOfRiskKeyIsItsOwn drives the real command: the
// journal refuses risk.key's own line (risk.key.replace), and the command
// has to answer "carried out, but nowhere on record" rather than ok. The
// wire name and the op differ here, which is exactly the case the watch
// used to miss.
func TestR3F02_TheAliasedRecordOfRiskKeyIsItsOwn(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "classifier.key")
	if err := os.WriteFile(keyPath, []byte("old-classifier-test-key\n"), 0o600); err != nil {
		t.Fatalf("write the classifier key: %v", err)
	}
	f := newFixture(t, func(c *Config) {
		c.RiskClassifier = RiskClassifierAI
		c.ExternalRiskObservationKeyFile = keyPath
		c.externalRiskClassifierFactory = func(string) risk.ExternalClassifier { return &iamt403KeyClassifier{} }
	})
	addPerson(t, f, "root", "admin", genSigner(t))

	full := func(e events.Event) error {
		if e.Type == events.EventAdminOp && e.Result == "risk.key.replace:ok" {
			return errors.New("write events.jsonl: there is not enough space on the disk")
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&full)
	defer f.gw.journalAppendFn.Store(nil)

	_, cerr := f.gw.runCommand("root", "risk.key", []byte(`{"proto":1,"key":"new-classifier-test-key"}`))
	if cerr == nil {
		t.Fatalf("risk.key answered ok with its own record (risk.key.replace) lost: the key was replaced and nothing in the journal says by whom - and the verdict on a lost record is what IAMT-451 exists for (F-02)")
	}
	if cerr.code != "E_AUDIT_UNAVAILABLE" {
		t.Errorf("risk.key answered %s (%s), want E_AUDIT_UNAVAILABLE: the replacement happened, and the answer has to say it is not on record", cerr.code, cerr.message)
	}
}

// TestR3F02_ALostApprovalRecordIsNotAnsweredOk drives risk.approve: the
// approval itself is granted in memory (one-time, spent by the next
// matching command) and the typed event is not the line the verdict looks
// at - the command writes one of its own now, and losing it has to be
// answered.
func TestR3F02_ALostApprovalRecordIsNotAnsweredOk(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	id := iamt394RefusedRed(t, f, "rm -rf /var/lib/postgresql")

	full := func(e events.Event) error {
		if e.Type == events.EventAdminOp && e.Result == "risk.approve:ok" {
			return errors.New("write events.jsonl: there is not enough space on the disk")
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&full)
	defer f.gw.journalAppendFn.Store(nil)

	_, cerr := f.gw.runCommand(f.person, "risk.approve", iamt394ApprovalRequest(t, id))
	if cerr == nil {
		t.Fatalf("risk.approve answered ok with the record of the approval lost: the approval is in force and will be spent by the next matching command, and the journal does not say who approved it (F-02)")
	}
	if cerr.code != "E_AUDIT_UNAVAILABLE" {
		t.Errorf("risk.approve answered %s (%s), want E_AUDIT_UNAVAILABLE: the approval was granted, and the answer has to say it is not on record", cerr.code, cerr.message)
	}
}
