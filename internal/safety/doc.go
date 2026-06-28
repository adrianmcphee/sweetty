// Package safety holds structural guardrail tests that lock the honeypot's
// safety doctrine in place. The handler packages that touch attacker input must
// never gain the ability to fetch a URL, execute input, write the host disk, or
// read the host /proc. The package doc-comments assert this in prose; the test
// here asserts it in code, so a regression that imports the capability fails the
// build instead of silently turning the sensor into an open relay or a malware
// drop.
package safety
