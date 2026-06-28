//go:build linux && amd64

package main

// auditArch is AUDIT_ARCH_X86_64 (EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE),
// the value the kernel reports in seccomp_data.arch for a native x86-64 syscall.
const auditArch = 0xC000003E
