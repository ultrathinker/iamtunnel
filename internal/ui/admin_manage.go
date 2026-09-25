//go:build windows || linux || darwin

package ui

import (
	"strings"

	"gioui.org/layout"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// admin_manage.go is the rest of SPEC §3.3 in the window (IAMT-499): "the
// tab and the console do the same thing". Until 24.09.2026 the console
// could verify a machine, change the account the gateway logs into on it,
// pin its new sshd key, add and remove a person's keys, print a person's
// connection string, and show, back up and rotate the gateway's own key --
// and the window could do none of it. The one that mattered: a machine
// whose sshd key had changed (hostKeyStatus "mismatch") keeps its door
// shut until an administrator confirms the new key, and from the window
// there was no way to.
//
// Each control here is keyed by the row's identity (the machine's ID, the
// person's name, the key's fingerprint), never by its position, for the
// reason every other row control on this tab gives: a list that re-sorts
// between fetches must never let one row's answer land under another's.

const (
	ctlAdminGatewayFingerprint = "admin/gateway/fingerprint"
	ctlAdminGatewayBackup      = "admin/gateway/backup"
	ctlAdminGatewayRotate      = "admin/gateway/rotate-hostkey"
)

// machineManageCtl and personKeysCtl name one row's disclosed panel.
func machineManageCtl(id string) string        { return "admin/manage/machine/" + id }
func personKeysCtl(name string) string         { return "admin/keys/person/" + name }
func personKeyRemoveCtl(ctl, fp string) string { return ctl + "/remove/" + fp }

// hostKeyMismatch reports whether the gateway is holding this machine's
// door shut over a changed sshd key.
func hostKeyMismatch(m AdminMachine) bool { return m.HostKeyStatus == "mismatch" }

// confirmKey is the confirming-map key of a two-press action whose
// question names a value typed into a box. The value is part of the key,
// so editing the box between the two presses asks again instead of
// sending something the question never named.
func confirmKey(ctl, value string) string { return ctl + "\x00" + value }

// askOrGo is the first or the second press of such an action: the first
// puts the question under the control, the second runs act. Any earlier
// question under the same control is forgotten on a first press.
func (f *Frame) askOrGo(ctl, value, question string, act func() (string, error)) {
	key := confirmKey(ctl, value)
	if !f.confirming[key] {
		for k := range f.confirming {
			if strings.HasPrefix(k, ctl+"\x00") {
				delete(f.confirming, k)
			}
		}
		f.confirming[key] = true
		f.say(ctl, question, design.WarnKey)
		return
	}
	delete(f.confirming, key)
	f.runAndRefresh(ctl, act)
}

// runAndRefresh sends one request and redraws the lists after it, success
// or not: a refusal can still mean the gateway's view moved.
func (f *Frame) runAndRefresh(ctl string, act func() (string, error)) {
	f.begin(ctl, "Asking the gateway.", func() (string, design.ColorKey) {
		defer f.refreshAdminLists()
		msg, err := act()
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// verifyMachine is "machines verify": the gateway probes the machine's
// sshd now and says what it found. One press, nothing changes but facts.
func (f *Frame) verifyMachine(ctl, id string) {
	verify := f.cfg.Actions.AdminMachineVerify
	if verify == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.runAndRefresh(ctl, func() (string, error) { return verify(id) })
}

// setMachineUser is "machines set-user". It shuts the door and re-probes,
// which the console asks --yes for; here it is the second press.
func (f *Frame) setMachineUser(ctl, id string) {
	user := strings.TrimSpace(f.editor(ctl + "/box").Text())
	if user == "" {
		f.say(ctl, `Type the OS account first: DOMAIN\name or MACHINE\name on Windows, a plain name elsewhere.`, design.BadKey)
		return
	}
	set := f.cfg.Actions.AdminMachineSetUser
	if set == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.askOrGo(ctl, user,
		"Log into "+id+" as "+user+"? The door shuts, and a fresh probe runs before it reopens. Press again to confirm.",
		func() (string, error) { return set(id, user) })
}

// rekeyMachine is "machines rekey": pin the sshd key the gateway observed.
// The fingerprint is typed back, not pre-filled: the whole point of the
// step is that somebody compared it with what the machine itself shows.
func (f *Frame) rekeyMachine(ctl, id string) {
	fp := strings.TrimSpace(f.editor(ctl + "/box").Text())
	if fp == "" {
		f.say(ctl, "Paste the fingerprint the machine's owner read out from the machine itself (SHA256:…).", design.BadKey)
		return
	}
	rekey := f.cfg.Actions.AdminMachineRekey
	if rekey == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.askOrGo(ctl, fp,
		"Pin "+fp+" as "+id+"'s sshd key? Do it only if the machine's owner confirmed this exact fingerprint on the machine. Press again to confirm.",
		func() (string, error) { return rekey(id, fp) })
}

// addPersonKey is "people keys add". Adding a key takes nothing away, so
// it is one press, like "Add person".
func (f *Frame) addPersonKey(ctl, name string) {
	key := strings.TrimSpace(f.editor(ctl + "/box").Text())
	if key == "" {
		f.say(ctl, "Paste the public key first (ssh-ed25519 AAAA…).", design.BadKey)
		return
	}
	add := f.cfg.Actions.AdminPersonKeyAdd
	if add == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.runAndRefresh(ctl, func() (string, error) { return add(name, key) })
}

// removePersonKey is "people keys remove", confirmed twice like every
// other removal on this tab.
func (f *Frame) removePersonKey(ctl, name, fp string) {
	remove := f.cfg.Actions.AdminPersonKeyRemove
	if remove == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.askOrGo(ctl, fp,
		"Remove key "+fp+" from "+name+"? New logins with it are refused; sessions already open go on. Press again to confirm.",
		func() (string, error) { return remove(name, fp) })
}

// personConnectionString is "people connection-string": the line handed
// to the person, given in a box that copies (IAMT-355's rule for every
// string the window hands out).
func (f *Frame) personConnectionString(ctl, name string) {
	cs := f.cfg.Actions.AdminPersonConnectionString
	if cs == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.beginGiving(ctl, "Asking the gateway.", func() (string, string, design.ColorKey) {
		line, err := cs(name)
		if err != nil {
			return "", err.Error(), design.BadKey
		}
		return line, "Hand this line to " + name + "; the Client tab of their window takes it.", design.GoodKey
	})
}

// gatewayFingerprint is "gateway fingerprint". The value is handed over in
// a copyable box: it is what an operator compares, character by character,
// against the one inside a connection string.
func (f *Frame) gatewayFingerprint() {
	fps := f.cfg.Actions.AdminGatewayFingerprint
	if fps == nil {
		f.say(ctlAdminGatewayFingerprint, noRuntime, design.BadKey)
		return
	}
	f.beginGiving(ctlAdminGatewayFingerprint, "Asking the gateway.", func() (string, string, design.ColorKey) {
		list, err := fps()
		if err != nil {
			return "", err.Error(), design.BadKey
		}
		if len(list) == 0 {
			return "", "The gateway reported no host key fingerprint.", design.BadKey
		}
		return strings.Join(list, "\n"),
			"Every connection string and enrol code this gateway hands out carries this fingerprint.", design.GoodKey
	})
}

// gatewayBackup is "gateway backup": a snapshot of state and journal kept
// on the gateway's own disk.
func (f *Frame) gatewayBackup() {
	backup := f.cfg.Actions.AdminGatewayBackup
	if backup == nil {
		f.say(ctlAdminGatewayBackup, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminGatewayBackup, "Asking the gateway.", func() (string, design.ColorKey) {
		msg, err := backup()
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// gatewayRotateHostkey is "gateway rotate-hostkey". v1 has no transition
// period (SPEC §6.2): after the restart that follows, every client and
// every machine holding the old fingerprint is refused -- this window
// included, until it is given a new connection string. The console asks
// --yes; the window asks twice and says all of that in the question.
func (f *Frame) gatewayRotateHostkey() {
	rotate := f.cfg.Actions.AdminGatewayRotateHostkey
	if rotate == nil {
		f.say(ctlAdminGatewayRotate, noRuntime, design.BadKey)
		return
	}
	if !f.confirming[ctlAdminGatewayRotate] {
		f.confirming[ctlAdminGatewayRotate] = true
		f.say(ctlAdminGatewayRotate,
			"Rotate the gateway's host key? Once the gateway restarts, EVERY client and machine with the old fingerprint is refused, this window too, until each gets a new connection string or is enrolled again. Press again to confirm.",
			design.WarnKey)
		return
	}
	f.confirming[ctlAdminGatewayRotate] = false
	f.begin(ctlAdminGatewayRotate, "Asking the gateway.", func() (string, design.ColorKey) {
		msg, err := rotate()
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// twoPressWord is the label of a two-press button: its own word, then
// "Confirm" while the question is up, then the busy word.
func (f *Frame) twoPressWord(ctl, value, word, busyWord string) string {
	switch {
	case f.busy(ctl):
		return busyWord
	case f.confirming[confirmKey(ctl, value)]:
		return "Confirm"
	}
	return word
}

// saidLine draws one control's status line, or nothing.
func (f *Frame) saidLine(gtx layout.Context, ctl string) layout.Dimensions {
	said := f.saidUnder(ctl)
	if said.text == "" {
		return layout.Dimensions{}
	}
	return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 300), said.key)
	})
}

// boxAndButton is one labelled box with its action button beside it and
// the action's status line under both.
func (f *Frame) boxAndButton(gtx layout.Context, ctl, label, hint, word string) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.End}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return design.Field(gtx, f.theme, label, func(gtx layout.Context) layout.Dimensions {
						return design.TextBox(gtx, f.theme, f.editor(ctl+"/box"), hint)
					}, "")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn(ctl), word)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.saidLine(gtx, ctl) }),
	)
}

// layoutMachineManage is one machine row's Manage panel, drawn under the
// row only while it is open (closed it costs no height, the rule
// layoutRowRename follows for gate 17's sake).
func (f *Frame) layoutMachineManage(gtx layout.Context, m AdminMachine) layout.Dimensions {
	ctl := machineManageCtl(m.ID)
	if !f.disclosedForm(ctl) {
		return layout.Dimensions{}
	}
	verifyCtl, userCtl, rekeyCtl := ctl+"/verify", ctl+"/user", ctl+"/rekey"
	if f.btn(verifyCtl).Clicked(gtx) {
		f.verifyMachine(verifyCtl, m.ID)
	}
	if f.btn(userCtl).Clicked(gtx) || f.submitted(gtx, userCtl+"/box") {
		f.setMachineUser(userCtl, m.ID)
	}
	mismatch := hostKeyMismatch(m)
	if mismatch && (f.btn(rekeyCtl).Clicked(gtx) || f.submitted(gtx, rekeyCtl+"/box")) {
		f.rekeyMachine(rekeyCtl, m.ID)
	}

	account := orDash(m.OSUser)
	if m.OSUserStatus != "" {
		account += " (" + m.OSUserStatus + ")"
	}
	hostKey := orDash(m.HostKeyStatus)
	if mismatch {
		hostKey = "CHANGED — the door stays shut until the new key is confirmed below"
	}
	verifyWord := "Verify now"
	if f.busy(verifyCtl) {
		verifyWord = "Probing…"
	}
	user := strings.TrimSpace(f.editor(userCtl + "/box").Text())
	rekeyFP := strings.TrimSpace(f.editor(rekeyCtl + "/box").Text())

	rows := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			facts := []design.FactRow{
				design.Fact("OS account", account),
				design.Fact("sshd host key", hostKey),
			}
			if mismatch && m.ObservedFingerprint != "" {
				facts = append(facts, design.Fact("key seen now", m.ObservedFingerprint))
			}
			return design.Facts(gtx, f.theme, facts)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn(verifyCtl), verifyWord)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.saidLine(gtx, verifyCtl) }),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return f.boxAndButton(gtx, userCtl, "log in as", `MACHINE\name`,
				f.twoPressWord(userCtl, user, "Set account", "Setting…"))
		}),
	}
	if mismatch {
		rows = append(rows,
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return f.boxAndButton(gtx, rekeyCtl, "confirm new key", "SHA256:… as read on the machine",
					f.twoPressWord(rekeyCtl, rekeyFP, "Pin new key", "Pinning…"))
			}))
	}
	return layout.Inset{Top: unit.Dp(design.Tight), Bottom: unit.Dp(design.Gap)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		})
}

// layoutPersonKeys is one person row's Keys panel: every key with its own
// Remove, a box to add one, and the person's connection string.
func (f *Frame) layoutPersonKeys(gtx layout.Context, p Person) layout.Dimensions {
	ctl := personKeysCtl(p.Name)
	if !f.disclosedForm(ctl) {
		return layout.Dimensions{}
	}
	addCtl, csCtl := ctl+"/add", ctl+"/cs"
	for _, k := range p.KeyList {
		if rm := personKeyRemoveCtl(ctl, k.Fingerprint); f.btn(rm).Clicked(gtx) {
			f.removePersonKey(rm, p.Name, k.Fingerprint)
		}
	}
	if f.btn(addCtl).Clicked(gtx) || f.submitted(gtx, addCtl+"/box") {
		f.addPersonKey(addCtl, p.Name)
	}
	if f.btn(csCtl).Clicked(gtx) {
		f.personConnectionString(csCtl, p.Name)
	}
	csWord := "Connection string"
	if f.busy(csCtl) {
		csWord = "Asking…"
	}

	var rows []layout.FlexChild
	if len(p.KeyList) == 0 {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme, "The gateway listed no keys for "+p.Name+".")
		}))
	}
	for _, k := range p.KeyList {
		k, rm := k, personKeyRemoveCtl(ctl, k.Fingerprint)
		rows = append(rows,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						line := k.Fingerprint
						if k.Added != "" {
							line += " · added " + k.Added
						}
						return design.Hint(gtx, f.theme, line)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.SecondaryButton(gtx, f.theme, f.btn(rm),
							f.twoPressWord(rm, k.Fingerprint, "Remove", "Removing…"))
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.saidLine(gtx, rm) }),
		)
	}
	addWord := "Add key"
	if f.busy(addCtl) {
		addWord = "Adding…"
	}
	rows = append(rows,
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return f.boxAndButton(gtx, addCtl, "another key", "ssh-ed25519 AAAA… person@laptop", addWord)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn(csCtl), csWord)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.saidLine(gtx, csCtl) }),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return f.layoutHandOver(gtx, csCtl, f.saidUnder(csCtl).give,
				"Copy connection string", "The connection string is on the clipboard.")
		}),
	)
	return layout.Inset{Top: unit.Dp(design.Tight), Bottom: unit.Dp(design.Gap)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		})
}

// layoutGatewaySection is the Gateway sub-tab: the gateway's own key and
// its state, the three "gateway" verbs the Admin tab did not have.
func (f *Frame) layoutGatewaySection(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlAdminGatewayFingerprint).Clicked(gtx) {
		f.gatewayFingerprint()
	}
	if f.btn(ctlAdminGatewayBackup).Clicked(gtx) {
		f.gatewayBackup()
	}
	if f.btn(ctlAdminGatewayRotate).Clicked(gtx) {
		f.gatewayRotateHostkey()
	}
	fpWord := "Show fingerprint"
	if f.busy(ctlAdminGatewayFingerprint) {
		fpWord = "Asking…"
	}
	backupWord := "Back up now"
	if f.busy(ctlAdminGatewayBackup) {
		backupWord = "Backing up…"
	}
	rotateWord := "Rotate host key"
	switch {
	case f.busy(ctlAdminGatewayRotate):
		rotateWord = "Rotating…"
	case f.confirming[ctlAdminGatewayRotate]:
		rotateWord = "Confirm"
	}
	button := func(btnCtl, word string, secondary bool) layout.FlexChild {
		return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if secondary {
						return design.SecondaryButton(gtx, f.theme, f.btn(btnCtl), word)
					}
					return design.CompactButton(gtx, f.theme, f.btn(btnCtl), word)
				}),
			)
		})
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		button(ctlAdminGatewayFingerprint, fpWord, false),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.saidLine(gtx, ctlAdminGatewayFingerprint) }),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return f.layoutHandOver(gtx, ctlAdminGatewayFingerprint, f.saidUnder(ctlAdminGatewayFingerprint).give,
				"Copy fingerprint", "The fingerprint is on the clipboard.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		button(ctlAdminGatewayBackup, backupWord, false),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme, "A snapshot of the gateway's state and journal, kept on the gateway's own disk.")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.saidLine(gtx, ctlAdminGatewayBackup) }),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		button(ctlAdminGatewayRotate, rotateWord, true),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme, "Only by the runbook, or when the key may be compromised: every client and machine is cut off until it gets a new connection string or is enrolled again.")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.saidLine(gtx, ctlAdminGatewayRotate) }),
	)
}
