//go:build !nogui

package main

// testedVariantWord is the word the build variant's name must carry in a
// test binary built WITHOUT -tags nogui (R1-CX F-05). Its twin in
// r1cx_f05_variant_headless_test.go answers for the headless run: the
// canary that tells the variants apart used to demand "full"
// unconditionally, so the documented go test -tags nogui ./... was red
// on that one test and on nothing else.
const testedVariantWord = "full"
