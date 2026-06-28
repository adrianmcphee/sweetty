//go:build linux && arm64

package main

// auditArch is AUDIT_ARCH_AARCH64 (EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE),
// the value the kernel reports in seccomp_data.arch for a native arm64 syscall.
const auditArch = 0xC00000B7
