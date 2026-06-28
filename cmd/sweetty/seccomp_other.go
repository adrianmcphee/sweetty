//go:build !linux

package main

// lockdownSyscalls is a no-op on non-Linux platforms. The honeypot is deployed on
// Linux, where the seccomp filter installs; this stub keeps `go build` and the test
// suite green during development on macOS.
func lockdownSyscalls() error { return nil }
