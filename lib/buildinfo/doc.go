package buildinfo

// Package buildinfo wires a -version flag and prints a build-version string
// injected via -ldflags during build. It also augments flag.Usage to include
// the version string in help output.