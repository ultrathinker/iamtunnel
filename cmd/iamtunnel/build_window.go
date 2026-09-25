//go:build (windows || linux || darwin) && !nogui

package main

// buildVariant is which of the two builds this binary is, in the words
// "iamtunnel version" prints (IAMT-439).
//
// TWO ARTEFACTS MEAN THE QUESTION "which version is on the gateway?"
// grows a second half, and a fact a person cannot read off the machine
// is a fact they will guess wrong. So the variant is printed always,
// beside the version and the platform -- never by its absence, which
// would make an old binary that predates the split look headless.
//
// The build tag here is the same one runGUI is split on, so the word
// cannot drift from the truth: if the window code is compiled in, this
// file is compiled in.
const buildVariant = "full (window included)"
