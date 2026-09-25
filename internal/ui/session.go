//go:build windows || linux || darwin

package ui

import (
	"context"
	"image"
	"image/color"
	"strings"
	"sync"
	"time"

	giofont "gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// Standard chunk size for sessions.tail requests (~256 KB per contract §1, §4).
// sessionListRefetch is how long an EMPTY session list is believed
// before the window asks again. It is not a poll of a value that
// changes slowly: it is the answer to the ordinary case where the
// machine's owner
// opens the tab first and the specialist connects a minute later.
const sessionListRefetch = 3 * time.Second

const tailChunkLimit = 256 * 1024

// heldByteCap is the maximum number of bytes the live-session tab keeps
// in memory as a contiguous replay range for backward scrollback
// (IAMT-341 round 2: an 8-hour session must not be held whole). 4 MiB
// is enough for the last ~16 fetches of the tail
// chunk, which is far beyond what a human will scroll back during a
// live monitor session; older bytes are simply dropped when this is
// reached.
const heldByteCap = 4 * 1024 * 1024

// sessionScreenState manages the live session tab: selection, background polling,
// .cast stream decoding, virtualized layout.List scrolling, and color rendering.
type sessionScreenState struct {
	frame *Frame

	mu         sync.Mutex
	selectedID string

	// views caches per-session terminal and tailing data.
	views map[string]*sessionView

	// pollCancel cancels the current poller's context (nil when tab closed
	// or idle). When the user switches sessions or closes the tab, the
	// caller invokes it so any in-flight tail request and any in-flight
	// backward load see ctx.Done() and stop — without this, a request sent
	// before the switch still arrives and still applies to a view the user
	// has already left.
	pollCancel context.CancelFunc
	// pollCtx is the context the poller is currently using; loadPreviousChunk
	// derives a child of it so the same cancellation propagates to the
	// backward load.
	pollCtx context.Context
	// pollGen bumps every time startPoller (or onTabClose, which calls
	// pollCancel) runs. Pollers and backward-load goroutines capture the
	// generation they were started with and check it before applying any
	// response — a stale goroutine that outlives its poller must not
	// write into the view it no longer owns.
	pollGen uint64

	// listFetched remembers whether Actions.SessionList has already been
	// called for this Session tab; the call is fire-and-forget and we do
	// not want to repeat it on every Layout pass while waiting for the
	// gateway's reply.
	listFetched bool

	// listInFlight guards against a second fetch while one is running:
	// the layout runs on every frame, and without it a slow gateway
	// would collect one goroutine per repaint.
	listInFlight bool

	// listFetchedAt is when the last fetch was started. An empty answer
	// is not final — the ordinary case is that the specialist connects
	// AFTER the machine's owner opened the tab — so an empty list is asked for
	// again, at the interval below rather than on every frame.
	listFetchedAt time.Time
	// listCache holds the result of the most recent SessionList call so
	// the tab has something to render before the snapshot updates.
	listCache []SessionInfo

	// listError holds the most recent SessionList failure — the empty
	// state at the top of the tab used to silently swallow it (the
	// machine's owner couldn't tell whether there were no sessions OR the gateway
	// was unreachable); now it surfaces, briefly, under the headline.
	listError string

	// exportMessage holds the outcome of the last Export press.
	exportMessage string
	exportKey     design.ColorKey

	// auditHook, renderHook, and interleaveHook are set only in tests via export_test.go.
	auditHook      func(isWrite bool)
	renderHook     func(index int, numHistory int, line record.Line)
	interleaveHook func()
}

// sessionView holds the virtual terminal emulator and stream progress for one session.
type sessionView struct {
	id string
	// Who is in and until when are NOT held here: the tab draws them
	// from the session list it just fetched, which is the gateway's
	// answer and therefore current. A copy on the view would be a
	// second, staler source of the same facts.
	vt         *record.VT
	held       []byte // bytes in [headOffset, offset), in stream order
	headOffset uint64 // earliest byte offset in .cast held (start of `held`)
	offset     uint64 // latest byte offset in .cast held (== headOffset + len(held))
	total      uint64 // total size of .cast file
	live       bool   // true while session is ongoing
	remainder  []byte // trailing partial line carried across record.ParseCast calls
	mode       string // how the bytes are read, as the gateway says (IAMT-453)

	// termList belongs to the view, not the tab: two sessions on the same
	// tab must NOT share a scroll position. Scrolling up in Alice's session
	// must not move Bob's session when the user switches between them.
	termList layout.List

	loadingPrev bool // true while fetching earlier chunk (scroll up)
}

// newSessionScreenState creates state for the Session tab.
func newSessionScreenState(f *Frame) *sessionScreenState {
	return &sessionScreenState{
		frame: f,
		views: make(map[string]*sessionView),
	}
}

// getView returns or creates a sessionView for the given session ID.
//
// MUST be called with s.mu held. It writes to s.views, and the map is
// reached from both the poll goroutines and the layout goroutine, so an
// unlocked call is a data race on the map itself - the kind that
// corrupts rather than merely reports a stale number. Every caller in
// this file takes the lock first; the race detector found the rule
// unwritten only because several tests called it bare.
func (s *sessionScreenState) getView(id string) *sessionView {
	v, ok := s.views[id]
	if !ok {
		v = &sessionView{
			id:   id,
			vt:   record.NewVT(80, 24),
			live: true,
			termList: layout.List{
				Axis:        layout.Vertical,
				ScrollToEnd: true,
			},
		}
		s.views[id] = v
	}
	return v
}

// activeSessions returns the active sessions visible to this window.
// For admin: sessions from AdminState or Actions.SessionList.
// For machine owner: sessions on this machine from ServerState.
//
// If both the admin snapshot and the server snapshot are empty AND a
// Actions.SessionList hook is configured, a fetch is kicked off the
// drawing goroutine (so the layout never blocks). The result is cached
// and surfaced on subsequent calls until the snapshot or the hook
// changes; this is what wires the declared-but-never-called
// Actions.SessionList from live.go (defect 6 of round 2).
func (s *sessionScreenState) activeSessions() []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	var list []SessionInfo
	seen := make(map[string]bool)

	// 1. Admin active sessions
	for _, sess := range s.frame.snap.Admin.ActiveSessions {
		id := sess.ID
		if id == "" {
			// Not watchable, and not inventable: see the comment on the
			// server branch below.
			continue
		}
		if !seen[id] {
			seen[id] = true
			list = append(list, SessionInfo{
				ID:      id,
				Person:  sess.Person,
				Machine: sess.Machine,
				Started: sess.Started,
				Until:   sess.Until,
			})
		}
	}

	// 2. Server sessions (machine owner's view)
	for _, sess := range s.frame.snap.Server.Sessions {
		id := sess.ID
		if id == "" {
			// A session id is the gateway's to mint, and this snapshot
			// does not carry one: the machine's own status reply cannot,
			// because the tunnel carries a nested SSH session whose bytes
			// the machine forwards without reading them.
			//
			// Earlier this branch filled the gap with "session-" plus the
			// person's name. That invented id went to the gateway, found
			// no recording (there is no such session anywhere), and came
			// back "not live" — so the machine's owner watched an empty terminal
			// while somebody really was working on the computer, and the
			// fabricated entry ALSO kept the list non-empty, which
			// stopped the real list from ever being asked for below.
			//
			// Skipping is what makes the real ids arrive: the list falls
			// through to Actions.SessionList, which asks the gateway
			// (IAMT-345 sessions.mine) and gets the ids it actually
			// minted.
			continue
		}
		if !seen[id] {
			seen[id] = true
			machine := sess.Machine
			if machine == "" {
				machine = s.frame.snap.Setup.MachineName
			}
			list = append(list, SessionInfo{
				ID:      id,
				Person:  sess.Person,
				Machine: machine,
				Started: sess.Started,
				Until:   sess.Until,
			})
		}
	}

	// 3. Fallback: if both snapshot sources were empty and the runtime
	// wired up Actions.SessionList, ask the gateway. The fetch runs in
	// the background; the cached result is appended once it arrives.
	if len(list) == 0 && s.frame.cfg.Actions.SessionList != nil && !s.listInFlight &&
		(!s.listFetched || time.Since(s.listFetchedAt) >= sessionListRefetch) {
		s.listFetched = true
		s.listInFlight = true
		s.listFetchedAt = time.Now()
		ask := s.frame.cfg.Actions.SessionList
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			infos, err := ask(ctx)
			s.mu.Lock()
			s.listInFlight = false
			if err == nil {
				s.listCache = infos
				s.listError = ""
			} else {
				s.listError = err.Error()
			}
			s.mu.Unlock()
			s.frame.repaint()
		}()
	}
	if len(list) == 0 && len(s.listCache) > 0 {
		for _, sess := range s.listCache {
			if !seen[sess.ID] {
				seen[sess.ID] = true
				list = append(list, sess)
			}
		}
	}

	return list
}

// onTabOpen starts polling for the active session when the Session tab opens.
func (s *sessionScreenState) onTabOpen() {
	sessions := s.activeSessions()
	if len(sessions) == 0 {
		return
	}

	s.mu.Lock()
	// Auto-select if exactly 1 session or if current selection is invalid
	found := false
	for _, sess := range sessions {
		if sess.ID == s.selectedID {
			found = true
			break
		}
	}
	if !found || s.selectedID == "" {
		s.selectedID = sessions[0].ID
	}
	targetID := s.selectedID
	s.mu.Unlock()

	s.startPoller(targetID)
}

// ensurePolling makes sure a poller is running for the currently
// selected session. Called from layoutSessionScreen on every frame so a
// session that begins WHILE the tab is open (user opens the tab first,
// a specialist connects a minute later) gets picked up without anybody
// clicking anything.
//
// No-op when no session is selected, when a poller is already running,
// or when the layout goroutine is racing a tab close — onTabClose
// nulls pollCancel and we honour that.
func (s *sessionScreenState) ensurePolling() {
	s.mu.Lock()
	targetID := s.selectedID
	hasCancel := s.pollCancel != nil
	s.mu.Unlock()

	if targetID == "" || hasCancel {
		return
	}
	s.startPoller(targetID)
}

// onTabClose stops background polling when the Session tab is closed:
// a closed tab gets no permanent polling stream. It also
// bumps pollGen so any in-flight tail request or backward-load
// goroutine sees the bump and stops writing into the view it no
// longer owns.
func (s *sessionScreenState) onTabClose() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pollCancel != nil {
		s.pollCancel()
		s.pollCancel = nil
	}
	s.pollCtx = nil
	s.pollGen++
}

// startPoller launches a 1-second polling loop for sessionID. It bumps
// pollGen and stores the new context so loadPreviousChunk can derive
// its child from the same source (a tab close or session switch then
// cancels them both at once).
func (s *sessionScreenState) startPoller(sessionID string) {
	s.mu.Lock()
	if s.pollCancel != nil {
		s.pollCancel()
		s.pollCancel = nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.pollCancel = cancel
	s.pollCtx = ctx
	s.pollGen++
	myGen := s.pollGen
	s.mu.Unlock()

	go func() {
		// A panic in the polling goroutine must not take the process
		// down (the goroutine that owns the Session tab also owns the
		// controls-and-stop tab). The standalone window already has its guard
		// (transcript_window.go); the polling loop lives here.
		defer guardWindow("session poller", nil)
		s.pollLoop(ctx, sessionID, myGen)
	}()
}

// pollLoop performs the initial tail fetch (~256 KB) and subsequent 1-second polls.
//
// myGen is the generation this poller was started with; before any
// write it checks s.pollGen still equals myGen. A poller that has been
// superseded by a session switch or a tab close sees the bump and
// exits without writing — defect 3 of round 2.
func (s *sessionScreenState) pollLoop(ctx context.Context, sessionID string, myGen uint64) {
	tail := s.frame.cfg.Actions.SessionTail
	if tail == nil {
		return
	}

	// Initial fetch: pull tail (~256 KB) if not already fetched.
	s.mu.Lock()
	if s.pollGen != myGen {
		s.mu.Unlock()
		return
	}
	v := s.getView(sessionID)
	curOffset := v.offset
	curTotal := v.total
	s.mu.Unlock()

	if curOffset == 0 && curTotal == 0 {
		// Where to open. The tab is called a live view, and a person who
		// opens it wants what is on the screen NOW - not the first
		// screens of a session that may have been running for hours.
		//
		// The first version asked for offset 0 and got exactly that: the
		// BEGINNING of the recording, one chunk of it, and then crawled
		// forward a chunk per second. On a session whose output has
		// outrun one chunk per tick the view never catches up at all,
		// and the machine's owner watches the distant past of their own
		// computer
		// while believing they are watching it live. Nothing in the tests
		// showed it, because every fixture answers with a recording
		// smaller than one chunk, where the beginning and the end are
		// the same place.
		//
		// So: one cheap probe to learn how big the recording is, then
		// open a window at its END. The probe asks for a single byte -
		// it is the `total` in the answer that is wanted, not the data.
		probe, perr := tail(ctx, SessionTailReq{ID: sessionID, Offset: 0, Limit: 1})
		start := uint64(0)
		if perr == nil && probe.Total > tailChunkLimit {
			start = probe.Total - tailChunkLimit
		}

		resp, err := tail(ctx, SessionTailReq{
			ID:     sessionID,
			Offset: start,
			Limit:  tailChunkLimit,
		})
		if err == nil {
			// The held range begins where this fetch began, not at zero:
			// applyForwardFetch appends, so the view must be told what
			// it is appending to. Scrolling up from here loads the
			// history that was skipped, which is exactly what the
			// backward extension exists for.
			s.mu.Lock()
			if s.pollGen != myGen {
				s.mu.Unlock()
				return
			}
			v = s.getView(sessionID)
			if len(v.held) == 0 {
				v.headOffset = start
				v.offset = start
			}
			s.mu.Unlock()

			shouldStop := s.applyForwardFetch(v, resp)
			if shouldStop {
				return
			}
			s.frame.repaint()
		}
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.pollGen != myGen {
				s.mu.Unlock()
				return
			}
			v = s.getView(sessionID)
			off := v.offset
			tot := v.total
			live := v.live
			s.mu.Unlock()

			// Stop polling when session is no longer live and read up to total:
			// live:false means nothing more will be added -- read up to
			// total and stop polling.
			if !live && off >= tot {
				return
			}

			resp, err := tail(ctx, SessionTailReq{
				ID:     sessionID,
				Offset: off,
				Limit:  tailChunkLimit,
			})
			if err != nil {
				continue
			}

			s.mu.Lock()
			if s.pollGen != myGen {
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
			shouldStop := s.applyForwardFetch(v, resp)

			s.frame.repaint()

			if shouldStop {
				return
			}
		}
	}
}

// applyForwardFetch feeds a forward tail response into the view:
// appends the new bytes to the held buffer, parses them into the
// existing VT (carrying the previous remainder), and updates total /
// live. Returns whether the poller should stop (session is no longer
// live AND we've caught up to total).
//
// The held buffer is capped at heldByteCap: a window cannot
// hold an eight-hour session in full. Forward overflow drops the
// oldest bytes from the front of held; v.headOffset advances to match,
// so the [v.headOffset, v.offset) contract stays intact. The VT is left
// alone — its history was already accumulated from those bytes — so
// the user keeps seeing the same screen content; a later backward
// rebuild from the trimmed held just won't include the dropped prefix.
//
// Takes s.mu itself rather than requiring the caller to do so, so a
// stale goroutine that survives a tab close or session switch cannot
// reach the view's fields without contending with the lock — the race
// condition on view fields fixed as round-2 defect 4. The audit counter
// lives next to the increment; the canary in
// zz_canary_sessionrace_test.go fails if either side drops the
// lock and the increment together.
func (s *sessionScreenState) applyForwardFetch(v *sessionView, resp SessionTailResp) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(resp.Data) > 0 {
		s.appendHeld(v, resp.Data)
		v.mode = resp.Mode
		v.remainder = record.ParserFor(v.mode)(resp.Data, v.remainder, v.vt)
	}
	v.total = resp.Total
	v.live = resp.Live
	if s.auditHook != nil {
		s.auditHook(true)
	}
	return !resp.Live && v.offset >= resp.Total
}

// appendHeld appends data to v.held, dropping the oldest bytes first
// if the result would exceed heldByteCap. Keeps [v.headOffset,
// v.offset) intact.
//
// Forward extension drops from the FRONT of v.held (oldest), never
// from `data` — data is the latest live bytes the viewer expects to
// see. If a single chunk were bigger than heldByteCap (it cannot
// happen today: tailChunkLimit is 256 KiB, heldByteCap is 4 MiB) we
// would still cap by truncating the head of `data`; the path is here
// so a future change that lifts tailChunkLimit cannot break the
// invariant.
//
// MUST be called with s.mu held.
func (s *sessionScreenState) appendHeld(v *sessionView, data []byte) {
	if len(data) == 0 {
		return
	}
	if len(v.held)+len(data) > heldByteCap {
		overflow := len(v.held) + len(data) - heldByteCap
		if overflow >= len(v.held) {
			// All of v.held would be dropped; data alone still must
			// fit. Take only its tail (the most recent bytes).
			droppedFromHeld := len(v.held)
			overflow -= droppedFromHeld
			v.headOffset += uint64(droppedFromHeld)
			v.held = nil
			// Truncate the front of data so it fits. The headOffset
			// advances past the dropped prefix.
			if uint64(len(data)) > uint64(overflow)+uint64(heldByteCap) {
				// data alone still exceeds cap — keep only its last
				// heldByteCap bytes.
				v.headOffset += uint64(len(data)) - uint64(heldByteCap)
				data = data[len(data)-heldByteCap:]
			} else {
				// data fits after dropping `overflow` from the front.
				v.headOffset += uint64(overflow)
				data = data[overflow:]
			}
		} else {
			v.held = v.held[overflow:]
			v.headOffset += uint64(overflow)
		}
	}
	v.held = append(v.held, data...)
	v.offset = v.headOffset + uint64(len(v.held))
}

// loadPreviousChunk pulls the preceding chunk of .cast data when the
// user scrolls to top: having reached the start of what is loaded,
// pull the preceding chunk with a smaller offset.
//
// The goroutine derives its context from the SAME parent as the current
// forward poller (s.pollCtx), so closing the tab or switching sessions
// cancels both at once — defect 2 of round 2. Before applying
// the response it checks pollGen so an in-flight load that has been
// superseded cannot write into the view it no longer owns — defect 3.
//
// The held buffer (v.held) is the source of truth: on success the new
// bytes are prepended and the VT is rebuilt from scratch by replaying
// the whole held range in order. Forward extension appends; backward
// extension rebuilds. Both paths keep [v.headOffset, v.offset) in
// stream order — a terminal is a sequential state machine, and feeding
// it bytes out of order corrupts the screen silently.
func (s *sessionScreenState) loadPreviousChunk(sessionID string) {
	tail := s.frame.cfg.Actions.SessionTail
	if tail == nil {
		return
	}

	s.mu.Lock()
	v := s.getView(sessionID)
	if v.headOffset == 0 || v.loadingPrev {
		s.mu.Unlock()
		return
	}
	v.loadingPrev = true
	head := v.headOffset
	myGen := s.pollGen
	parentCtx := s.pollCtx
	s.mu.Unlock()

	if parentCtx == nil {
		// No poller is active (test harness or initial state). Refuse
		// rather than fire a request that nothing else can cancel.
		s.mu.Lock()
		v.loadingPrev = false
		s.mu.Unlock()
		return
	}

	go func() {
		// A panic in the backward-load goroutine must not take the
		// process down (the goroutine that owns the Session tab also
		// owns the controls-and-stop tab). The standalone window already has its
		// guard; this one lives here.
		defer guardWindow("session backward loader", nil)
		defer func() {
			s.mu.Lock()
			v.loadingPrev = false
			s.mu.Unlock()
		}()

		ctx, cancel := context.WithCancel(parentCtx)
		defer cancel()

		var prevOffset uint64
		var limit uint32
		if head > tailChunkLimit {
			prevOffset = head - tailChunkLimit
			limit = tailChunkLimit
		} else {
			prevOffset = 0
			limit = uint32(head)
		}

		resp, err := tail(ctx, SessionTailReq{
			ID:     sessionID,
			Offset: prevOffset,
			Limit:  limit,
		})
		if err != nil || len(resp.Data) == 0 {
			return
		}

		s.mu.Lock()
		if s.pollGen != myGen {
			s.mu.Unlock()
			return
		}
		s.extendBackward(v, resp.Data, prevOffset)
		s.mu.Unlock()

		s.frame.repaint()
	}()
}

// extendBackward prepends newBytes (loaded from [newHead, headOffset))
// to v.held and rebuilds the VT by replaying the full held range in
// order. The cap is enforced by dropping the oldest bytes from the
// FRONT of (newBytes ++ v.held) — i.e. newBytes first, then v.held —
// so a prepend that would push the held range past heldByteCap simply
// refuses part of the oldest portion instead of failing the load.
// That loss is reflected by the rebuild (the new VT has no state from
// the dropped prefix).
//
// The replayed range almost never starts at byte 0 (the initial tail
// fetch lands mid-recording). State that existed before the replay
// window — cursor position, SGR, scrollback, the last clear — is
// therefore lost, and the first screens the viewer shows after this
// are approximate. This is a fact of mid-stream replay, not a bug;
// the comment on record.VT.Reset says the same thing on the emulator
// side.
//
// MUST be called with s.mu held.
func (s *sessionScreenState) extendBackward(v *sessionView, newBytes []byte, newHead uint64) {
	// (newBytes ++ v.held) is the new held range after the prepend.
	// Front = newBytes; the bytes that get dropped on overflow come
	// from newBytes first, then v.held.
	if len(v.held)+len(newBytes) > heldByteCap {
		overflow := len(v.held) + len(newBytes) - heldByteCap
		if overflow >= len(newBytes) {
			overflow -= len(newBytes)
			newHead += uint64(len(newBytes))
			if overflow > len(v.held) {
				overflow = len(v.held)
			}
			v.held = v.held[overflow:]
			newHead += uint64(overflow)
			newBytes = nil
		} else {
			newBytes = newBytes[overflow:]
			newHead += uint64(overflow)
		}
	}
	held := make([]byte, 0, len(v.held)+len(newBytes))
	held = append(held, newBytes...)
	held = append(held, v.held...)
	v.held = held
	v.headOffset = newHead
	v.offset = newHead + uint64(len(held))

	cols, rows := 80, 24
	if v.vt != nil {
		cols, rows = v.vt.Size()
	}
	fresh := record.NewVT(cols, rows)
	v.remainder = record.ParserFor(v.mode)(v.held, nil, fresh)
	v.vt = fresh
}

// layoutSessionScreen renders the Session tab (IAMT-341, contract §4).
//
// Gate 17 invariant: The terminal panel occupies the remaining available vertical space
// and scrolls inside itself (via termList); it NEVER grows downward to cause an outer
// page scrollbar, ensuring 0 scroll-thumb pixels at the default window size.
func (f *Frame) layoutSessionScreen(gtx layout.Context) layout.Dimensions {
	if f.sessionUI == nil {
		f.sessionUI = newSessionScreenState(f)
	}
	uiState := f.sessionUI
	sessions := uiState.activeSessions()

	// Empty state: worded explicitly (no sessions -- the tab says so
	// in words rather than showing emptiness).
	//
	// Even here we still call activeSessions on every frame: it is the
	// only thing that asks the gateway (Actions.SessionList) when the
	// snapshot is empty, and the only thing that refreshes the empty
	// answer to "now there is one". The fallback below is the literal
	// layout the empty card needs; the call above is what makes the
	// empty state ever end.
	if len(sessions) == 0 {
		// Capture any gateway error so the empty state says WHICH of
		// "no sessions" or "gateway unreachable" the user is looking
		// at. The empty card otherwise looks identical for both.
		uiState.mu.Lock()
		listErr := uiState.listError
		uiState.mu.Unlock()
		// The error is folded into the existing card body so we do
		// not push the page over the default window (Gate 17). The
		// Said-style status line was tried first; it grew the page
		// by exactly the pixels this gate measures.
		body := "No active terminal sessions on this machine or gateway. " +
			"When a specialist enters a session, their commands and terminal output will appear here live in real time."
		if listErr != "" {
			body += "\n\nCould not reach the gateway: " + listErr
		}
		// design.WideDp, not Gap: every other screen is laid out by
		// design.PinnedPage, which insets the page by Wide on all four
		// sides. This one builds its own Flex and used Gap, so the
		// heading sat twenty pixels higher than the heading of every
		// other tab -- visible the moment the screens are put side by
		// side, which is what the maintainer asked for on 21.09.2026.
		return layout.Inset{
			Top:   design.WideDp,
			Left:  design.EdgeDp,
			Right: design.EdgeDp,
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(posterOf(f.theme, "No active sessions right now", "Session", design.InkKey)),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(cardOf(f.theme, "Live terminal view", func(gtx layout.Context) layout.Dimensions {
					return design.Words(gtx, f.theme,
						body,
						design.BodySp, design.MutedKey, f.theme.BodyFont)
				})),
			)
		})
	}

	// Ensure selection is valid
	uiState.mu.Lock()
	found := false
	for _, sess := range sessions {
		if sess.ID == uiState.selectedID {
			found = true
			break
		}
	}
	if !found {
		uiState.selectedID = sessions[0].ID
	}
	selID := uiState.selectedID
	uiState.mu.Unlock()

	// Auto-pickup: a session that started while the tab was open still
	// has to be polled, even though onTabOpen only ran when the tab was
	// empty. Without this, the selected session silently shows a frozen
	// terminal until the user switches tabs and back.
	uiState.ensurePolling()

	// Handle Export button press — OFF the drawing goroutine. The export
	// walks the whole .cast stream and writes files to disk, and a window
	// that runs it inline stops repainting for the whole export:
	// export holds the drawing thread. The status line under the button
	// tells the person the work is happening.
	if f.btn(ctlSessionExport).Clicked(gtx) {
		if exp := f.cfg.Actions.SessionExport; exp != nil {
			f.begin(ctlSessionExport, "Exporting.", func() (string, design.ColorKey) {
				msg, err := exp(selID)
				if err != nil {
					return "Export failed: " + err.Error(), design.BadKey
				}
				return msg, design.GoodKey
			})
		} else {
			f.say(ctlSessionExport, noRuntime, design.BadKey)
		}
	}

	return layout.Inset{
		Top:    unit.Dp(design.Gap),
		Left:   design.EdgeDp,
		Right:  design.EdgeDp,
		Bottom: unit.Dp(design.Tight),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// 1. Top bar: session switcher or compact title, status, export button
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return f.layoutSessionTopBar(gtx, sessions, selID)
			}),
			// Status line if Export was clicked
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if uiState.exportMessage == "" {
					return layout.Dimensions{}
				}
				return layout.Inset{Top: unit.Dp(design.Tight), Bottom: unit.Dp(design.Tight)}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, f.theme, f.sel("session/export/said"), uiState.exportMessage, uiState.exportKey)
					})
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			// 2. Terminal viewport: occupies exact available height (Gate 17 compliant)
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return f.layoutSessionTerminal(gtx, selID)
			}),
		)
	})
}

// layoutSessionTopBar renders the top switcher bar:
// When >1 sessions: buttons to switch between them.
// When 1 session: compact header without distracting controls.
func (f *Frame) layoutSessionTopBar(gtx layout.Context, sessions []SessionInfo, selectedID string) layout.Dimensions {
	uiState := f.sessionUI

	if len(sessions) == 1 {
		// Single session: Compact title, switcher doesn't get in the way
		s := sessions[0]
		mach := s.Machine
		if mach == "" {
			mach = f.snap.Setup.MachineName
		}
		lead := "Live session — " + orDash(clipStr(s.Person, 24))
		if mach != "" {
			lead += " on " + orDash(clipStr(mach, 24))
		}
		if !s.Until.IsZero() {
			lead += " · until " + untilText(s.Until)
		}

		return layout.Flex{
			Axis:      layout.Horizontal,
			Alignment: layout.Middle,
		}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Dot(gtx, f.theme, design.GoodKey, false)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return design.Deck(gtx, f.theme, lead)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.SecondaryButton(gtx, f.theme, f.btn(ctlSessionExport), "Export session")
			}),
		)
	}

	// Multiple sessions: Switcher row with one button per session
	var items []layout.FlexChild
	for _, sess := range sessions {
		sess := sess
		isSel := sess.ID == selectedID
		btnKey := "session/pick/" + sess.ID

		if f.btn(btnKey).Clicked(gtx) {
			uiState.mu.Lock()
			uiState.selectedID = sess.ID
			uiState.mu.Unlock()
			uiState.startPoller(sess.ID)
		}

		label := sess.Person
		if label == "" {
			label = sess.ID
		}
		if sess.Machine != "" {
			label += " (" + sess.Machine + ")"
		}

		items = append(items,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if isSel {
					return design.PrimaryButton(gtx, f.theme, f.btn(btnKey), label)
				}
				return design.SecondaryButton(gtx, f.theme, f.btn(btnKey), label)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(design.Tight)}.Layout),
		)
	}

	items = append(items,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, 0)}
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.SecondaryButton(gtx, f.theme, f.btn(ctlSessionExport), "Export session")
		}),
	)

	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, items...)
}

// layoutSessionTerminal renders the virtualized terminal pane with scrollback and live screen grid.
//
// ALL VT reads happen under uiState.mu in a single critical section: a
// fetch goroutine writes to the same VT via record.ParseCast under the
// same lock (applyForwardFetch, extendBackward), and a layout that read
// HistoryTotal, Screen, Cursor and History across several calls would
// see the VT grow or shrink between them — processRune moves rows from
// the screen into history as it scrolls, so numHistory can change while
// we are still iterating. The list fed to termList.Layout is therefore a
// SNAPSHOT built inside the lock, not four separate VT calls that the
// draw goroutine then walks.
//
// The shape is the same defect the maintainer hit on 19.09.2026 in
// live_watch.go (commit d129a8d): two goroutines touching one terminal
// emulator, where one is the fetch and the other is the draw. The fix is
// the same — read everything once into locals, draw from them — and the
// canary in zz_canary_sessionrace_test.go breaks the rule in both
// directions so a future revert on either side catches it.
func (f *Frame) layoutSessionTerminal(gtx layout.Context, sessionID string) layout.Dimensions {
	uiState := f.sessionUI

	// Snapshot EVERYTHING we will need before releasing the lock. The
	// history slice and the screen slice are copied out of the VT here
	// (the VT's own methods make copies under its RWMutex), so the
	// callback that runs later cannot be invalidated by a ParseCast that
	// lands in between. history is capped to the tail end (the lines the
	// list actually lays out: termList.Position.First onward, up to
	// remaining-capacity), so the snapshot's size is bounded by what the
	// user can see.
	uiState.mu.Lock()
	v := uiState.getView(sessionID)
	loadingPrev := v.loadingPrev
	headOffset := v.headOffset
	live := v.live
	firstPos := v.termList.Position.First

	// Build the snapshot the list will iterate. totalItems mirrors the
	// same arithmetic the old code did (history lines + screen rows).
	// The history slice only needs the part the list is about to draw:
	// any lines scrolled above firstPos are skipped by termList.Layout
	// and need not be copied.
	numHistory := v.vt.HistoryTotal()
	if uiState.interleaveHook != nil {
		uiState.interleaveHook()
	}
	screenLines := v.vt.Screen()
	cursorX, cursorY := v.vt.Cursor()

	historyStart := firstPos
	if historyStart > numHistory {
		historyStart = numHistory
	}
	historyLines := v.vt.History(historyStart, numHistory-historyStart)
	// Copy screenLines defensively: vt.Screen() returns a fresh slice,
	// but the Line values inside reference the VT's screenAttr buffer
	// and could in principle be re-used. The terminal copy is already a
	// deep enough snapshot for our renderTerminalLine consumption, but
	// making our own copy here keeps the contract local.
	screenCopy := append([]record.Line(nil), screenLines...)
	if uiState.auditHook != nil {
		uiState.auditHook(false)
	}
	uiState.mu.Unlock()

	totalItems := numHistory + len(screenCopy)

	// Trigger a backward load when the user has scrolled to the top of
	// the held range AND there is older data still available. The four
	// condition pieces are read under the lock above so a concurrent
	// extendBackward cannot leave us looking at stale state — round-2
	// defect 4.
	if firstPos == 0 && headOffset > 0 && !loadingPrev {
		uiState.loadPreviousChunk(sessionID)
	}

	// Terminal background styling
	pal := f.theme.Palette
	bgColor := pal.Surface
	if !pal.IsDark {
		bgColor = pal.Sunken
	}

	border := widget.Border{
		Color:        f.theme.Color(design.LineKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(design.Radius),
	}

	return border.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		paint.FillShape(gtx.Ops, bgColor, clip.Rect(image.Rect(0, 0, gtx.Constraints.Max.X, gtx.Constraints.Max.Y)).Op())

		return layout.Inset{
			Top:    unit.Dp(design.Pad),
			Bottom: unit.Dp(design.Pad),
			Left:   unit.Dp(design.Pad),
			Right:  unit.Dp(design.Pad),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			// termList.Layout iterates from firstPos..firstPos+visible.
			// The snapshot is indexed by ABSOLUTE positions in the
			// history+screen sequence, but historyLines only holds the
			// slice starting at firstPos, so the iteration index needs
			// to be translated.
			return v.termList.Layout(gtx, totalItems, func(gtx layout.Context, index int) layout.Dimensions {
				if index < numHistory {
					histIdx := index - firstPos
					if histIdx < 0 {
						histIdx = 0
					}
					var line record.Line
					if histIdx >= 0 && histIdx < len(historyLines) {
						line = historyLines[histIdx]
					}
					if uiState.renderHook != nil {
						uiState.renderHook(index, numHistory, line)
					}
					return f.renderTerminalLine(gtx, line, false, -1)
				}
				// Live screen row
				row := index - numHistory
				var line record.Line
				if row >= 0 && row < len(screenCopy) {
					line = screenCopy[row]
				}
				if uiState.renderHook != nil {
					uiState.renderHook(index, numHistory, line)
				}
				isCursorRow := (row == cursorY && live)
				return f.renderTerminalLine(gtx, line, isCursorRow, cursorX)
			})
		})
	})
}

// renderTerminalLine formats and paints a single terminal line with Attr colors and cursor.
func (f *Frame) renderTerminalLine(gtx layout.Context, line record.Line, isCursorRow bool, cursorCol int) layout.Dimensions {
	runes := []rune(line.Text)
	lineLen := len(runes)

	// In monospaced font, pad line if cursor is beyond text length
	targetLen := lineLen
	if isCursorRow && cursorCol >= targetLen {
		targetLen = cursorCol + 1
	}

	var children []layout.FlexChild
	col := 0

	for col < targetLen {
		attr := record.Attr{}
		if col < len(line.Attrs) {
			attr = line.Attrs[col]
		}
		isCursor := (isCursorRow && col == cursorCol)

		// Collect contiguous span of runes sharing the same style
		var sb strings.Builder

		for col < targetLen {
			curAttr := record.Attr{}
			if col < len(line.Attrs) {
				curAttr = line.Attrs[col]
			}
			curIsCursor := (isCursorRow && col == cursorCol)

			if curIsCursor != isCursor || curAttr != attr {
				break
			}

			if col < lineLen {
				sb.WriteRune(runes[col])
			} else {
				sb.WriteRune(' ')
			}
			col++
		}

		spanText := sb.String()
		spanAttr := attr
		spanCursor := isCursor

		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return f.renderTerminalSpan(gtx, spanText, spanAttr, spanCursor)
		}))
	}

	if len(children) == 0 {
		// Empty line placeholder
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Label(f.theme.Material, design.SmallSp, " ")
			lbl.Font = f.theme.MonoFont
			return lbl.Layout(gtx)
		}))
	}

	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
}

// renderTerminalSpan paints one span with specific SGR colors, styles, or cursor highlighting.
func (f *Frame) renderTerminalSpan(gtx layout.Context, text string, attr record.Attr, isCursor bool) layout.Dimensions {
	pal := f.theme.Palette

	// Default foreground and background colors
	defFG := pal.Ink
	defBG := color.NRGBA{A: 0} // Transparent by default

	fg := resolveColor(attr.FG, defFG)
	bg := resolveColor(attr.BG, defBG)

	if attr.Reverse {
		fg, bg = bg, fg
		if fg.A == 0 {
			fg = pal.Page
		}
	}

	if isCursor {
		// Invert/highlight cursor cell
		bg = pal.Spot
		fg = pal.OnSpot
	}

	lbl := material.Label(f.theme.Material, design.SmallSp, text)
	lbl.Font = f.theme.MonoFont
	if attr.Bold {
		lbl.Font.Weight = giofont.Bold
	}
	lbl.Color = fg

	macro := op.Record(gtx.Ops)
	dims := lbl.Layout(gtx)
	call := macro.Stop()

	if bg.A > 0 {
		paint.FillShape(gtx.Ops, bg, clip.Rect(image.Rect(0, 0, dims.Size.X, dims.Size.Y)).Op())
	}
	call.Add(gtx.Ops)

	if attr.Underline {
		// Draw underline hairline
		lineY := dims.Size.Y - 1
		paint.FillShape(gtx.Ops, fg, clip.Rect(image.Rect(0, lineY, dims.Size.X, dims.Size.Y)).Op())
	}

	return dims
}

// Standard ANSI 16 color table.
var ansi16Colors = [16]color.NRGBA{
	0:  {R: 0, G: 0, B: 0, A: 255},       // Black
	1:  {R: 194, G: 54, B: 33, A: 255},   // Red
	2:  {R: 37, G: 188, B: 36, A: 255},   // Green
	3:  {R: 173, G: 173, B: 39, A: 255},  // Yellow
	4:  {R: 73, G: 46, B: 225, A: 255},   // Blue
	5:  {R: 211, G: 56, B: 211, A: 255},  // Magenta
	6:  {R: 51, G: 187, B: 200, A: 255},  // Cyan
	7:  {R: 203, G: 204, B: 205, A: 255}, // White
	8:  {R: 129, G: 131, B: 131, A: 255}, // Bright Black (Gray)
	9:  {R: 252, G: 57, B: 31, A: 255},   // Bright Red
	10: {R: 49, G: 231, B: 34, A: 255},   // Bright Green
	11: {R: 234, G: 236, B: 35, A: 255},  // Bright Yellow
	12: {R: 88, G: 51, B: 255, A: 255},   // Bright Blue
	13: {R: 249, G: 53, B: 248, A: 255},  // Bright Magenta
	14: {R: 20, G: 240, B: 240, A: 255},  // Bright Cyan
	15: {R: 233, G: 235, B: 235, A: 255}, // Bright White
}

// resolveColor converts a contract record.Color into a concrete color.NRGBA.
func resolveColor(c record.Color, defaultCol color.NRGBA) color.NRGBA {
	switch c.Kind {
	case record.ColorNamed:
		return ansi16Colors[c.Index&0x0f]
	case record.Color256:
		return xterm256Color(c.Index)
	case record.ColorRGB:
		return color.NRGBA{R: c.R, G: c.G, B: c.B, A: 255}
	default:
		return defaultCol
	}
}

// xterm256Color resolves 256-color palette index to RGB.
func xterm256Color(idx uint8) color.NRGBA {
	if idx < 16 {
		return ansi16Colors[idx]
	}
	if idx >= 232 {
		gray := uint8(8 + (int(idx)-232)*10)
		return color.NRGBA{R: gray, G: gray, B: gray, A: 255}
	}
	idx -= 16
	b := idx % 6
	g := (idx / 6) % 6
	r := idx / 36
	toVal := func(v uint8) uint8 {
		if v == 0 {
			return 0
		}
		return 55 + v*40
	}
	return color.NRGBA{R: toVal(r), G: toVal(g), B: toVal(b), A: 255}
}

// setSessionVT is a test hook to inject a virtual terminal state for unit tests.
func (f *Frame) setSessionVT(sessionID string, vt *record.VT) {
	if f.sessionUI == nil {
		f.sessionUI = newSessionScreenState(f)
	}
	f.sessionUI.mu.Lock()
	v := f.sessionUI.getView(sessionID)
	v.vt = vt
	f.sessionUI.selectedID = sessionID
	f.sessionUI.mu.Unlock()
}
