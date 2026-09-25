# Contributing

Thanks for looking at iamtunnel. This is a young project maintained by one
person, so please open an issue before a large pull request — small fixes and
documentation improvements are always welcome without one.

## Building

Go 1.27 or later.

```
go build -o iamtunnel ./cmd/iamtunnel        # full build (Windows: no cgo needed)
go build -tags nogui -o iamtunnel ./cmd/iamtunnel   # headless build (gateway), no cgo anywhere
```

The full build (with the GUI) uses [Gio](https://gioui.org), which talks to
the platform windowing system through cgo on Linux and macOS. The headless
build (`-tags nogui`) drops `internal/ui` entirely and never needs cgo — it is
what ships on the gateway. Windows does not need cgo for either build.

On Linux, building the full GUI needs the desktop dev packages: `libx11-dev
libxkbcommon-dev libxkbcommon-x11-dev libxcursor-dev libxfixes-dev
libwayland-dev libvulkan-dev libegl1-mesa-dev libgles2-mesa-dev` (headers only — nothing is opened at build
time).

## Testing

```
go test ./...
```

Before sending a pull request, run the full gate suite locally:

```
powershell -File scripts/gates.ps1   # Windows
./scripts/gates.sh                   # Linux/macOS
```

This runs `go vet`, `staticcheck`, `govulncheck`, the race-enabled test suite,
binary size checks, and the project's own structural gates (raw file I/O
outside `internal/datafile`, event/error dictionary consistency, and so on).

## Code style

- Run `gofmt` before committing; CI does not reformat for you.
- Comments explain *why*, not *what* — the code already says what it does.
- Keep `docs/SPEC.md` and `docs/PROTOCOL.md` section numbers intact if you
  touch them; code comments cite them by number.

## Pull requests

- One logical change per pull request; keep the diff reviewable.
- Update the relevant doc (`docs/SPEC.md`, `docs/PROTOCOL.md`,
  `docs/RUNBOOK.md`, `docs/THREATS.md`) alongside a behavior change — the
  gates check that `docs/PROTOCOL.md` and `docs/RUNBOOK.md` stay consistent
  with the code's event and error dictionaries.
- Describe what you tested, especially for anything touching the door
  lifecycle, authentication, or the recording pipeline.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same as the rest of the project
(section 5 of the license).
