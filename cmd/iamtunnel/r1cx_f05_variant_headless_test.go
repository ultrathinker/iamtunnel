//go:build nogui

package main

// testedVariantWord for a test binary built WITH -tags nogui: the
// headless variant, the one that ships to a gateway (R1-CX F-05; see
// r1cx_f05_variant_full_test.go).
const testedVariantWord = "headless"
