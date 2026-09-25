// Command extract_windows_icon dumps every PNG embedded in the iamtunnel
// Windows .syso resource (cmd/iamtunnel/rsrc_windows_amd64.syso) as a
// standalone .png file. The output directory is created if absent.
//
// Why this exists: iamtunnel has only the compiled .syso as its icon
// source — there is no .ico/.png in git and no go:generate / rsrc
// directive in the repo. When the .desktop file (Linux) and the
// .icns bundle (macOS) need a single source of truth for the app icon
// (IAMT-255, IAMT-298), the canonical asset is the PNGs this tool
// dumps into assets/icon/iamtunnel-<size>.png. To regenerate after
// an icon redesign:
//
//	# from repo root
//	go run ./tools/extract_windows_icon
//
// and commit the resulting PNGs. The .syso itself is the binary
// build of a stock app icon (kept under cmd/iamtunnel/rsrc_windows_amd64.syso).
//
// The tool only reads PNG signatures inside the .rsrc section of the
// COFF object; it does NOT use Windows Resource APIs (this is a
// cross-build tool, not a Win32 program). It assumes the resource
// layout is "PNG bytes concatenated in size order" — the shape the
// stock icon-pack toolchain produces and that this repo's .syso
// matches; if the .syso ever changes shape, dump one entry with
// `go run ./tools/extract_windows_icon -probe` and look at the
// reported offsets.
//
// Run without args: dumps to assets/icon/ next to the .syso file.
// Run with -probe: prints the offsets and sizes of every PNG and
// exits without writing (useful for debugging a regression).
//
// Run with -out DIR: writes to DIR instead of the default.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"os"
	"path/filepath"
)

// defaultIconPath matches cmd/iamtunnel/rsrc_windows_amd64.syso at the
// repo root. Computed relative to the executable's directory so the
// tool runs the same way from any cwd.
func defaultIconPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "rsrc_windows_amd64.syso"
	}
	// Walk up from the binary to find a go.mod that identifies the
	// repo root.
	dir := filepath.Dir(exe)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "cmd", "iamtunnel", "rsrc_windows_amd64.syso")
		}
		dir = filepath.Dir(dir)
	}
	return "cmd/iamtunnel/rsrc_windows_amd64.syso"
}

func main() {
	iconPath := flag.String("icon", defaultIconPath(), "path to rsrc_windows_amd64.syso")
	outDir := flag.String("out", "", "output directory for the PNGs (default: assets/icon next to the .syso)")
	probe := flag.Bool("probe", false, "print offsets/sizes only, do not write files")
	flag.Parse()

	data, err := os.ReadFile(*iconPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract_windows_icon: read %s: %v\n", *iconPath, err)
		os.Exit(2)
	}

	offsets := findPNGs(data)
	if len(offsets) == 0 {
		fmt.Fprintf(os.Stderr, "extract_windows_icon: no PNG signatures found in %s\n", *iconPath)
		os.Exit(1)
	}
	if *probe {
		fmt.Printf("%s: %d PNG(s)\n", *iconPath, len(offsets))
		for i, o := range offsets {
			fmt.Printf("  [%d] offset=%d size=%d\n", i, o.start, o.size)
		}
		return
	}

	dest := *outDir
	if dest == "" {
		// Default to assets/icon next to the .syso so the tool can
		// be run from anywhere.
		exe, _ := os.Executable()
		dir := filepath.Dir(exe)
		for i := 0; i < 6; i++ {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				dest = filepath.Join(dir, "assets", "icon")
				break
			}
			dir = filepath.Dir(dir)
		}
		if dest == "" {
			dest = "assets/icon"
		}
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "extract_windows_icon: mkdir %s: %v\n", dest, err)
		os.Exit(1)
	}

	for _, o := range offsets {
		raw := data[o.start : o.start+o.size]
		w, h := pngDimensions(raw)
		name := fmt.Sprintf("iamtunnel-%d.png", w)
		out := filepath.Join(dest, name)
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "extract_windows_icon: write %s: %v\n", out, err)
			os.Exit(1)
		}
		fmt.Printf("  %s (%dx%d, %d bytes)\n", out, w, h, len(raw))
	}
	fmt.Printf("wrote %d PNG(s) under %s\n", len(offsets), dest)
}

// pngSpan is one PNG inside the .syso: start offset and size in bytes.
// Size is computed to the next PNG signature, or to the IEND chunk for
// the very last image, which is what the standard layout (PNG bytes
// concatenated in order) produces.
type pngSpan struct {
	start int
	size  int
}

// findPNGs scans data for the standard PNG signature (89 50 4E 47 0D 0A
// 1A 0A) and returns every PNG's start offset and size. The size
// heuristic is "next PNG signature OR end of file"; if the last image is
// not the last byte of the file the caller will see a slightly truncated
// dump. The IAMT-247 .syso puts IEND as the very last bytes of every
// PNG, so this is fine for the assets in this repo.
func findPNGs(data []byte) []pngSpan {
	const sig = "\x89PNG\r\n\x1a\n"
	var out []pngSpan
	searchFrom := 0
	for searchFrom < len(data) {
		next := bytes.Index(data[searchFrom:], []byte(sig))
		if next < 0 {
			break
		}
		start := searchFrom + next
		rest := data[start+len(sig):]
		after := bytes.Index(rest, []byte(sig))
		var size int
		if after < 0 {
			// Last PNG: bound on IEND (4 bytes type + 4 bytes CRC
			// + 4 bytes preceding length = 12 bytes from "IEND").
			e := bytes.Index(rest, []byte("IEND"))
			if e < 0 {
				size = len(data) - start
			} else {
				size = start + len(sig) + e + 12 - start
			}
		} else {
			size = len(sig) + after
		}
		out = append(out, pngSpan{start: start, size: size})
		searchFrom = start + size
	}
	return out
}

// pngDimensions decodes just the IHDR chunk of raw (PNG signature +
// length + "IHDR" + width + height) and returns the pixel size. The
// helper panics on a malformed PNG: the only callsite is a tool over
// a known-good .syso, and a malformed PNG means the tool itself is
// wrong.
func pngDimensions(raw []byte) (int, int) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		// Fall back to reading IHDR bytes directly so the tool still
		// produces a sensible filename even when the input is somehow
		// not decodable by the stdlib decoder.
		if len(raw) < 24 {
			fmt.Fprintf(os.Stderr, "extract_windows_icon: PNG too short to parse IHDR\n")
			os.Exit(1)
		}
		w := int(uint32(raw[16])<<24 | uint32(raw[17])<<16 | uint32(raw[18])<<8 | uint32(raw[19]))
		h := int(uint32(raw[20])<<24 | uint32(raw[21])<<16 | uint32(raw[22])<<8 | uint32(raw[23]))
		return w, h
	}
	return cfg.Width, cfg.Height
}
